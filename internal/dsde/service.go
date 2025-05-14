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
	fg           *split.FG
	pgB          int
	kmsClient    *kms.Client
	kmsKeyID     string
	db           *db.Client
	store        *storage.Client
	statsEnabled bool
}

// NewService constructs it.
func NewService(
	fg *split.FG,
	pgB int,
	kmsClient *kms.Client,
	kmsKeyID string,
	dbClient *db.Client,
	storeClient *storage.Client,
	statsEnabled bool,

) *Service {
	return &Service{
		fg:           fg,
		pgB:          pgB,
		kmsClient:    kmsClient,
		kmsKeyID:     kmsKeyID,
		db:           dbClient,
		store:        storeClient,
		statsEnabled: statsEnabled,
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

	// 1) Read the entire file
	data, readErr := io.ReadAll(r)
	if readErr != nil {
		log.Error("read file", zap.Error(readErr))
		err = readErr
		return
	}

	// 2) Compute FG
	feaHash, err = s.fg.Feature(bytes.NewReader(data))
	if err != nil {
		log.Error("compute feature", zap.Error(err))
		return
	}

	// 3) First PG split → pkg1, pkg2_orig
	pkg1, pkg2_orig := split.PG(feaHash, data, s.pgB)
	pkg2Len := len(pkg2_orig)

	// 4) Get-or-create shared DEK
	var sharedCipher []byte
	if sharedCipher, err = s.db.GetFeatureByFeaHash(feaHash); errors.Is(err, sql.ErrNoRows) {
		out, gerr := s.kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
			KeyId:   &s.kmsKeyID,
			KeySpec: "AES_256",
		})
		if gerr != nil {
			log.Error("GenerateDataKey(shared)", zap.Error(gerr))
			err = gerr
			return
		}
		sharedCipher = out.CiphertextBlob
		if err = s.db.CreateFeature(feaHash, sharedCipher); err != nil {
			log.Error("CreateFeature", zap.Error(err))
			return
		}
	} else if err != nil {
		log.Error("GetFeatureByFeaHash", zap.Error(err))
		return
	}
	dekShared = sharedCipher

	// 5) Decrypt shared DEK
	resp1, derr := s.kmsClient.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: dekShared})
	if derr != nil {
		log.Error("Decrypt shared DEK", zap.Error(derr))
		err = derr
		return
	}
	enc1, err := encryption.NewWithKey(resp1.Plaintext)
	if err != nil {
		log.Error("NewWithKey(shared)", zap.Error(err))
		return
	}

	// 6) Encrypt pkg1 → pkg3C
	pkg3C, err := enc1.Encrypt(pkg1, true)
	if err != nil {
		log.Error("Encrypt pkg1", zap.Error(err))
		return
	}

	// 7) Second PG split on pkg3C → d, pkg4
	d, pkg4 := split.PG(feaHash, pkg3C, s.pgB)

	// 8) Generate user DEK
	out2, uerr := s.kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &s.kmsKeyID,
		KeySpec: "AES_256",
	})
	if uerr != nil {
		log.Error("GenerateDataKey(user)", zap.Error(uerr))
		err = uerr
		return
	}
	dekUser = out2.CiphertextBlob
	enc2, err := encryption.NewWithKey(out2.Plaintext)
	if err != nil {
		log.Error("NewWithKey(user)", zap.Error(err))
		return
	}

	// 9) Encrypt pkg2_orig||pkg4 → sBlob
	combined := append(pkg2_orig, pkg4...)
	sBlob, err := enc2.Encrypt(combined, false)
	if err != nil {
		log.Error("Encrypt combined", zap.Error(err))
		return
	}

	// 10) Persist file record (remember pkg2Len)
	fileID, err = s.db.CreateFileWithMeta(ownerID, filename, feaHash, dekShared, dekUser, pkg2Len)
	if err != nil {
		log.Error("CreateFileWithMeta", zap.Error(err))
		return
	}

	// 11) Store & dedupe “d”
	hashD := sha256.Sum256(d)
	hexD := fmt.Sprintf("%x", hashD[:])
	keyD := "common/" + hexD

	existed, err := s.db.ExistsChunk(hexD)
	if err != nil {
		log.Error("ExistsChunk", zap.Error(err))
		return
	}
	if !existed {
		if err = s.store.PutObject(ctx, keyD, bytes.NewReader(d)); err != nil {
			log.Error("PutObject(common)", zap.Error(err))
			return
		}
		if err = s.db.InsertChunk(hexD, keyD, true); err != nil {
			log.Error("InsertChunk(common)", zap.Error(err))
			return
		}
	}
	if err = s.db.AddFileChunk(fileID, hexD, 0); err != nil {
		log.Error("AddFileChunk(common)", zap.Error(err))
		return
	}

	// 12) Store sBlob
	hashS := sha256.Sum256(sBlob)
	hexS := fmt.Sprintf("%x", hashS[:])
	keyS := fmt.Sprintf("files/%s/s-%s", fileID, hexS)
	if err = s.store.PutObject(ctx, keyS, bytes.NewReader(sBlob)); err != nil {
		log.Error("PutObject(sBlob)", zap.Error(err))
		return
	}
	if err = s.db.InsertChunk(hexS, keyS, false); err != nil {
		log.Error("InsertChunk(sBlob)", zap.Error(err))
		return
	}
	if err = s.db.AddFileChunk(fileID, hexS, 1); err != nil {
		log.Error("AddFileChunk(sBlob)", zap.Error(err))
		return
	}

	log.Info("upload complete", zap.String("fileID", fileID))

	// ── print per-upload stats if enabled ───────────────────────────────────
	if s.statsEnabled {
		saved := 0
		if existed {
			saved = len(d)
		}
		total := len(d) + len(sBlob)
		pct := float64(saved) / float64(total) * 100
		fmt.Printf(
			"→ dedupe stats for file %s: reused %d bytes; saved %.1f%% of this upload’s payload\n",
			fileID, saved, pct,
		)
	}

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
