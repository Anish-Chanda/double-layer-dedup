package dsde

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Anish-Chanda/double-layer-dedup/internal/db"
	"github.com/Anish-Chanda/double-layer-dedup/internal/encryption" // Correct package
	"github.com/Anish-Chanda/double-layer-dedup/internal/split"
	"github.com/Anish-Chanda/double-layer-dedup/internal/storage"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"go.uber.org/zap"
)

// Service holds the DSDE logic and dependencies.
type Service struct {
	fg        *split.FG
	pgB       int
	kmsClient *kms.Client
	kmsKeyID  string
	db        *db.Client
	store     *storage.Client
}

// NewService constructs it.
func NewService(
	fg *split.FG,
	pgB int,
	kmsClient *kms.Client,
	kmsKeyID string,
	dbClient *db.Client,
	storeClient *storage.Client,
) *Service {
	return &Service{
		fg:        fg,
		pgB:       pgB,
		kmsClient: kmsClient,
		kmsKeyID:  kmsKeyID,
		db:        dbClient,
		store:     storeClient,
	}
}

// Upload implements the paper’s upload with double-layer encryption and dedupe.
func (s *Service) Upload(
	ctx context.Context,
	ownerID, filename string,
	r io.Reader,
) (fileID string, feaHash, dekShared, dekUser []byte, err error) {
	log := zap.L().Named("Upload")
	log.Debug("start", zap.String("owner", ownerID), zap.String("file", filename))

	// 1) read file
	data, readErr := io.ReadAll(r)
	if readErr != nil {
		log.Error("read file", zap.Error(readErr))
		err = readErr
		return
	}
	log.Debug("read data", zap.Int("bytes", len(data)))

	// 2) FG
	var fgErr error
	feaHash, fgErr = s.fg.Feature(bytes.NewReader(data))
	if fgErr != nil {
		log.Error("compute feature", zap.Error(fgErr))
		err = fgErr
		return
	}
	log.Debug("computed feaHash", zap.String("feaHash", fmt.Sprintf("%x", feaHash)))

	// 3) PG split original → pkg1, pkg2
	pkg1, pkg2_orig := split.PG(feaHash, data, s.pgB)
	pkg2Len := len(pkg2_orig)
	log.Debug("PG split original", zap.Int("len_pkg1", len(pkg1)), zap.Int("len_pkg2_orig", pkg2Len))

	// 4) REUSE or GENERATE shared DEK
	var retrievedCipher []byte
	var dbQueryError error
	retrievedCipher, dbQueryError = s.db.GetFeatureByFeaHash(feaHash)

	if dbQueryError != nil {
		if errors.Is(dbQueryError, sql.ErrNoRows) {
			log.Debug("new feature, generating shared DEK", zap.String("feaHash", fmt.Sprintf("%x", feaHash)))
			out1, genKeyErr := s.kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
				KeyId:   &s.kmsKeyID,
				KeySpec: "AES_256",
			})
			if genKeyErr != nil {
				log.Error("GenerateDataKey(shared)", zap.Error(genKeyErr))
				err = genKeyErr
				return
			}
			dekShared = out1.CiphertextBlob
			if dekShared == nil || len(dekShared) == 0 {
				err = errors.New("KMS GenerateDataKey returned empty CiphertextBlob for shared DEK")
				log.Error("empty sharedCipher after generation", zap.Error(err))
				return
			}

			if createFeatureErr := s.db.CreateFeature(feaHash, dekShared); createFeatureErr != nil {
				log.Error("CreateFeature", zap.Error(createFeatureErr))
				err = createFeatureErr
				return
			}
			log.Debug("new shared DEK created and stored", zap.String("feaHash", fmt.Sprintf("%x", feaHash)), zap.Int("len_cipher", len(dekShared)))
		} else {
			log.Error("GetFeatureByFeaHash", zap.Error(dbQueryError), zap.String("feaHash", fmt.Sprintf("%x", feaHash)))
			err = dbQueryError
			return
		}
	} else {
		dekShared = retrievedCipher
		log.Debug("reuse shared DEK", zap.String("feaHash", fmt.Sprintf("%x", feaHash)), zap.Int("len_cipher", len(dekShared)))
		if dekShared == nil || len(dekShared) == 0 {
			err = fmt.Errorf("reused shared DEK from DB is empty for feaHash %x", feaHash)
			log.Error("critical: empty shared DEK from DB on reuse", zap.String("feaHash", fmt.Sprintf("%x", feaHash)), zap.Error(err))
			return
		}
	}

	// 5) Decrypt shared DEK to plaintext
	var resp1 *kms.DecryptOutput
	var decryptSharedErr error
	resp1, decryptSharedErr = s.kmsClient.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: dekShared})
	if decryptSharedErr != nil {
		log.Error("Decrypt shared DEK", zap.Error(decryptSharedErr), zap.String("feaHash", fmt.Sprintf("%x", feaHash)))
		err = decryptSharedErr
		return
	}
	var enc1 *encryption.Service // CORRECTED TYPE
	var enc1Err error
	enc1, enc1Err = encryption.NewWithKey(resp1.Plaintext) // NewWithKey returns *encryption.Service
	if enc1Err != nil {
		log.Error("encryption.NewWithKey(shared)", zap.Error(enc1Err))
		err = enc1Err
		return
	}

	// 6) Encrypt pkg1 → pkg3C
	var pkg3C []byte
	var encryptPkg1Err error
	pkg3C, encryptPkg1Err = enc1.Encrypt(pkg1, true)
	if encryptPkg1Err != nil {
		log.Error("Encrypt pkg1", zap.Error(encryptPkg1Err))
		err = encryptPkg1Err
		return
	}
	log.Debug("encrypted pkg1→pkg3C", zap.Int("len", len(pkg3C)))

	// 7) PG split pkg3C → d, pkg4_from_split
	d, pkg4_from_split := split.PG(feaHash, pkg3C, s.pgB)
	log.Debug("PG split pkg3C", zap.Int("len_d", len(d)), zap.Int("len_pkg4_from_split", len(pkg4_from_split)))

	// 8) Generate user DEK
	var out2 *kms.GenerateDataKeyOutput
	var genUserKeyErr error
	out2, genUserKeyErr = s.kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &s.kmsKeyID,
		KeySpec: "AES_256",
	})
	if genUserKeyErr != nil {
		log.Error("GenerateDataKey user", zap.Error(genUserKeyErr))
		err = genUserKeyErr
		return
	}
	dekUser = out2.CiphertextBlob
	log.Debug("generated user DEK", zap.Int("len_cipher", len(dekUser)))
	var enc2 *encryption.Service // CORRECTED TYPE
	var enc2Err error
	enc2, enc2Err = encryption.NewWithKey(out2.Plaintext) // NewWithKey returns *encryption.Service
	if enc2Err != nil {
		log.Error("encryption.NewWithKey(user)", zap.Error(enc2Err))
		err = enc2Err
		return
	}

	// 9) Encrypt pkg2_orig || pkg4_from_split → sBlob
	combinedForSBlob := append(pkg2_orig, pkg4_from_split...)
	var sBlob []byte
	var encryptCombinedErr error
	sBlob, encryptCombinedErr = enc2.Encrypt(combinedForSBlob, false)
	if encryptCombinedErr != nil {
		log.Error("Encrypt combinedForSBlob", zap.Error(encryptCombinedErr))
		err = encryptCombinedErr
		return
	}
	log.Debug("encrypted combinedForSBlob→sBlob", zap.Int("len", len(sBlob)))

	// 10) Persist file metadata
	var createFileMetaErr error
	fileID, createFileMetaErr = s.db.CreateFileWithMeta(ownerID, filename, feaHash, dekShared, dekUser, pkg2Len)
	if createFileMetaErr != nil {
		log.Error("CreateFileWithMeta", zap.Error(createFileMetaErr))
		err = createFileMetaErr
		return
	}
	log.Info("file record created", zap.String("fileID", fileID), zap.Int("pkg2Len_stored", pkg2Len))

	// 11) Store & dedupe “d”
	hashD := sha256.Sum256(d)
	hexD := fmt.Sprintf("%x", hashD[:])
	keyD := "common/" + hexD
	var existsChunkErr error
	var exists bool
	exists, existsChunkErr = s.db.ExistsChunk(hexD)
	if existsChunkErr != nil {
		log.Error("ExistsChunk", zap.Error(existsChunkErr))
		err = existsChunkErr
		return
	}
	log.Debug("chunk exists?", zap.String("chunk_d_hash", hexD), zap.Bool("exists", exists))
	if !exists {
		if putCommonErr := s.store.PutObject(ctx, keyD, bytes.NewReader(d)); putCommonErr != nil {
			log.Error("PutObject common (d)", zap.Error(putCommonErr))
			err = putCommonErr
			return
		}
		if insertChunkCommonErr := s.db.InsertChunk(hexD, keyD, true); insertChunkCommonErr != nil {
			log.Error("InsertChunk common (d)", zap.Error(insertChunkCommonErr))
			err = insertChunkCommonErr
			return
		}
		log.Debug("common chunk (d) stored", zap.String("chunk_d_hash", hexD))
	}
	if addFileChunkCommonErr := s.db.AddFileChunk(fileID, hexD, 0); addFileChunkCommonErr != nil {
		log.Error("AddFileChunk common (d)", zap.Error(addFileChunkCommonErr))
		err = addFileChunkCommonErr
		return
	}

	// 12) Store sBlob
	hashS := sha256.Sum256(sBlob)
	hexS := fmt.Sprintf("%x", hashS[:])
	keyS := fmt.Sprintf("files/%s/s-%s", fileID, hexS)
	if putSBlobErr := s.store.PutObject(ctx, keyS, bytes.NewReader(sBlob)); putSBlobErr != nil {
		log.Error("PutObject sBlob", zap.Error(putSBlobErr))
		err = putSBlobErr
		return
	}
	if insertChunkSBlobErr := s.db.InsertChunk(hexS, keyS, false); insertChunkSBlobErr != nil {
		log.Error("InsertChunk sBlob", zap.Error(insertChunkSBlobErr))
		err = insertChunkSBlobErr
		return
	}
	if addFileChunkSBlobErr := s.db.AddFileChunk(fileID, hexS, 1); addFileChunkSBlobErr != nil {
		log.Error("AddFileChunk sBlob", zap.Error(addFileChunkSBlobErr))
		err = addFileChunkSBlobErr
		return
	}

	log.Info("upload complete", zap.String("fileID", fileID))
	return
}

// Download reverses the upload steps to reconstruct F.
func (s *Service) Download(
	ctx context.Context,
	ownerID, fileID string,
) (io.ReadCloser, error) {
	log := zap.L().Named("Download")
	log.Debug("start", zap.String("owner", ownerID), zap.String("fileID", fileID))

	// 1) Metadata + chunk infos
	meta, chunks, err := s.db.GetFileMeta(ownerID, fileID)
	if err != nil {
		log.Error("GetFileMeta", zap.Error(err), zap.String("fileID", fileID))
		return nil, err
	}
	if len(chunks) != 2 {
		err = fmt.Errorf("expected 2 chunks, got %d for fileID %s", len(chunks), fileID)
		log.Error("Chunk count error", zap.Error(err))
		return nil, err
	}
	pkg2Len_stored := meta.Pkg2Len
	log.Debug("meta+chunks loaded", zap.Int("pkg2Len_stored", pkg2Len_stored), zap.Any("chunks", chunks))

	// 2) Decrypt shared DEK
	resp1, err := s.kmsClient.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: meta.DekShared,
	})
	if err != nil {
		log.Error("Decrypt shared DEK", zap.Error(err), zap.String("fileID", fileID))
		return nil, err
	}
	enc1, err := encryption.NewWithKey(resp1.Plaintext) // CORRECTED: NewWithKey returns *encryption.Service, error
	if err != nil {
		log.Error("NewWithKey(shared)", zap.Error(err), zap.String("fileID", fileID))
		return nil, err
	}

	// 3) Fetch dData
	dRc, err := s.store.GetObject(ctx, chunks[0].S3Key)
	if err != nil {
		log.Error("GetObject dData", zap.Error(err), zap.String("s3Key", chunks[0].S3Key), zap.String("fileID", fileID))
		return nil, err
	}
	dData, readErr := io.ReadAll(dRc)
	dRc.Close()
	if readErr != nil {
		log.Error("ReadAll dData", zap.Error(readErr), zap.String("fileID", fileID))
		return nil, readErr
	}
	log.Debug("read dData", zap.Int("len", len(dData)))

	// 4) Decrypt user DEK
	resp2, err := s.kmsClient.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: meta.DekUser,
	})
	if err != nil {
		log.Error("Decrypt user DEK", zap.Error(err), zap.String("fileID", fileID))
		return nil, err
	}
	enc2, err := encryption.NewWithKey(resp2.Plaintext) // CORRECTED: NewWithKey returns *encryption.Service, error
	if err != nil {
		log.Error("NewWithKey(user)", zap.Error(err), zap.String("fileID", fileID))
		return nil, err
	}

	// 5) Fetch & decrypt sBlob → combinedForSBlob_decrypted
	sRc, err := s.store.GetObject(ctx, chunks[1].S3Key)
	if err != nil {
		log.Error("GetObject sBlob", zap.Error(err), zap.String("s3Key", chunks[1].S3Key), zap.String("fileID", fileID))
		return nil, err
	}
	sBlob, readErr := io.ReadAll(sRc)
	sRc.Close()
	if readErr != nil {
		log.Error("ReadAll sBlob", zap.Error(readErr), zap.String("fileID", fileID))
		return nil, readErr
	}
	combinedForSBlob_decrypted, err := enc2.Decrypt(sBlob)
	if err != nil {
		log.Error("Decrypt sBlob", zap.Error(err), zap.String("fileID", fileID))
		return nil, err
	}
	log.Debug("combinedForSBlob_decrypted", zap.Int("len", len(combinedForSBlob_decrypted)))

	// 6) Split combinedForSBlob_decrypted using pkg2Len_stored
	if pkg2Len_stored < 0 || pkg2Len_stored > len(combinedForSBlob_decrypted) {
		err = fmt.Errorf("invalid pkg2Len_stored %d for combinedForSBlob_decrypted length %d. FileID: %s", pkg2Len_stored, len(combinedForSBlob_decrypted), fileID)
		log.Error("pkg2Len_stored split error", zap.Error(err))
		return nil, err
	}
	original_pkg2_retrieved := combinedForSBlob_decrypted[:pkg2Len_stored]
	pkg4_from_split_retrieved := combinedForSBlob_decrypted[pkg2Len_stored:]
	log.Debug("split combinedForSBlob_decrypted", zap.Int("len_original_pkg2_retrieved", len(original_pkg2_retrieved)), zap.Int("len_pkg4_from_split_retrieved", len(pkg4_from_split_retrieved)))

	// 7) Reconstruct pkg3C from dData & pkg4_from_split_retrieved
	lf_pkg3C := len(dData) + len(pkg4_from_split_retrieved)
	D_pkg3C_mask := make([]bool, lf_pkg3C)
	for i := 1; i <= s.pgB; i++ {
		h := sha256.New()
		h.Write(meta.FeaHash)
		var idx [8]byte
		binary.BigEndian.PutUint64(idx[:], uint64(i))
		h.Write(idx[:])
		pos := binary.BigEndian.Uint64(h.Sum(nil)[:8]) % uint64(lf_pkg3C)
		D_pkg3C_mask[pos] = true
	}

	pkg3C := make([]byte, lf_pkg3C)
	di_pkg3C, p4i_pkg3C := 0, 0
	for j := 0; j < lf_pkg3C; j++ {
		if D_pkg3C_mask[j] {
			if p4i_pkg3C >= len(pkg4_from_split_retrieved) {
				err = fmt.Errorf("reconstruction error (pkg3C): p4i_pkg3C out of bounds. p4i: %d, len: %d. FileID: %s", p4i_pkg3C, len(pkg4_from_split_retrieved), fileID)
				log.Error("Boundary error p4i_pkg3C", zap.Error(err))
				return nil, err
			}
			pkg3C[j] = pkg4_from_split_retrieved[p4i_pkg3C]
			p4i_pkg3C++
		} else {
			if di_pkg3C >= len(dData) {
				err = fmt.Errorf("reconstruction error (pkg3C): di_pkg3C out of bounds. di: %d, len: %d. FileID: %s", di_pkg3C, len(dData), fileID)
				log.Error("Boundary error di_pkg3C", zap.Error(err))
				return nil, err
			}
			pkg3C[j] = dData[di_pkg3C]
			di_pkg3C++
		}
	}
	if p4i_pkg3C != len(pkg4_from_split_retrieved) {
		err = fmt.Errorf("reconstruction error (pkg3C): not all bytes from pkg4_from_split_retrieved used. p4i: %d, len: %d. FileID: %s", p4i_pkg3C, len(pkg4_from_split_retrieved), fileID)
		log.Error("Consumption mismatch pkg4_from_split_retrieved", zap.Error(err))
		return nil, err
	}
	if di_pkg3C != len(dData) {
		err = fmt.Errorf("reconstruction error (pkg3C): not all bytes from dData used. di: %d, len: %d. FileID: %s", di_pkg3C, len(dData), fileID)
		log.Error("Consumption mismatch dData", zap.Error(err))
		return nil, err
	}
	log.Debug("reconstructed pkg3C", zap.Int("len", len(pkg3C)))

	// 8) Decrypt pkg3C → original_pkg1_retrieved
	original_pkg1_retrieved, err := enc1.Decrypt(pkg3C)
	if err != nil {
		log.Error("Decrypt pkg3C", zap.Error(err), zap.String("fileID", fileID))
		return nil, err
	}
	log.Debug("decrypted original_pkg1_retrieved", zap.Int("len", len(original_pkg1_retrieved)))

	// 9) Merge original_pkg1_retrieved + original_pkg2_retrieved
	lf_original := len(original_pkg1_retrieved) + len(original_pkg2_retrieved)
	D_original_mask := make([]bool, lf_original)
	for i := 1; i <= s.pgB; i++ {
		h := sha256.New()
		h.Write(meta.FeaHash)
		var idx [8]byte
		binary.BigEndian.PutUint64(idx[:], uint64(i))
		h.Write(idx[:])
		pos := binary.BigEndian.Uint64(h.Sum(nil)[:8]) % uint64(lf_original)
		D_original_mask[pos] = true
	}

	outputFileBytes := make([]byte, lf_original)
	i1_orig, i2_orig := 0, 0
	for j := 0; j < lf_original; j++ {
		if D_original_mask[j] {
			if i2_orig >= len(original_pkg2_retrieved) {
				err = fmt.Errorf("reconstruction error (original file): i2_orig out of bounds. i2: %d, len: %d. FileID: %s", i2_orig, len(original_pkg2_retrieved), fileID)
				log.Error("Boundary error i2_orig", zap.Error(err))
				return nil, err
			}
			outputFileBytes[j] = original_pkg2_retrieved[i2_orig]
			i2_orig++
		} else {
			if i1_orig >= len(original_pkg1_retrieved) {
				err = fmt.Errorf("reconstruction error (original file): i1_orig out of bounds. i1: %d, len: %d. FileID: %s", i1_orig, len(original_pkg1_retrieved), fileID)
				log.Error("Boundary error i1_orig", zap.Error(err))
				return nil, err
			}
			outputFileBytes[j] = original_pkg1_retrieved[i1_orig]
			i1_orig++
		}
	}
	if i2_orig != len(original_pkg2_retrieved) {
		err = fmt.Errorf("reconstruction error (original file): not all bytes from original_pkg2_retrieved used. i2: %d, len: %d. FileID: %s", i2_orig, len(original_pkg2_retrieved), fileID)
		log.Error("Consumption mismatch original_pkg2_retrieved", zap.Error(err))
		return nil, err
	}
	if i1_orig != len(original_pkg1_retrieved) {
		err = fmt.Errorf("reconstruction error (original file): not all bytes from original_pkg1_retrieved used. i1: %d, len: %d. FileID: %s", i1_orig, len(original_pkg1_retrieved), fileID)
		log.Error("Consumption mismatch original_pkg1_retrieved", zap.Error(err))
		return nil, err
	}

	log.Info("download complete", zap.String("fileID", fileID), zap.Int("bytes_out", len(outputFileBytes)))
	return io.NopCloser(bytes.NewReader(outputFileBytes)), nil
}
