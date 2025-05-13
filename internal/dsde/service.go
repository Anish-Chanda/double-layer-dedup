package dsde

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/Anish-Chanda/double-layer-dedup/internal/db"
	"github.com/Anish-Chanda/double-layer-dedup/internal/encryption"
	"github.com/Anish-Chanda/double-layer-dedup/internal/split"
	"github.com/Anish-Chanda/double-layer-dedup/internal/storage"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type Service struct {
	fg        *split.FG
	pgB       int
	kmsClient *kms.Client
	kmsKeyID  string
	db        *db.Client
	store     *storage.Client
}

func NewService(
	fg *split.FG,
	pgB int,
	kmsClient *kms.Client,
	kmsKeyID string,
	dbClient *db.Client,
	storeClient *storage.Client,
) *Service {
	return &Service{fg: fg, pgB: pgB, kmsClient: kmsClient, kmsKeyID: kmsKeyID, db: dbClient, store: storeClient}
}

func (s *Service) Upload(
	ctx context.Context,
	ownerID, filename string,
	r io.Reader,
) (fileID string, feaHash, dekShared, dekUser []byte, err error) {
	// 1) read file
	data, err := io.ReadAll(r)
	if err != nil {
		return
	}

	// 2) FG
	feaHash, err = s.fg.Feature(bytes.NewReader(data))
	if err != nil {
		return
	}

	// 3) PG → pkg1, pkg2
	pkg1, pkg2 := split.PG(feaHash, data, s.pgB)

	// 4) REUSE or GENERATE shared DEK
	var sharedCipher []byte
	sharedCipher, err = s.db.GetFeatureByFeaHash(feaHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// first uploader: generate & persist
			out1, err2 := s.kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
				KeyId:   &s.kmsKeyID,
				KeySpec: "AES_256",
			})
			if err2 != nil {
				err = err2
				return
			}
			sharedCipher = out1.CiphertextBlob
			if err2 = s.db.CreateFeature(feaHash, sharedCipher); err2 != nil {
				err = err2
				return
			}
		} else {
			return
		}
	}
	dekShared = sharedCipher

	// 5) Decrypt shared DEK to plaintext
	resp1, err := s.kmsClient.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: sharedCipher})
	if err != nil {
		return
	}
	enc1, err := encryption.NewWithKey(resp1.Plaintext)
	if err != nil {
		return
	}

	// 6) Encrypt pkg1 → pkg3C
	pkg3C, err := enc1.Encrypt(pkg1, true)
	if err != nil {
		return
	}

	// 7) PG(pkg3C) → d, pkg4
	d, pkg4 := split.PG(feaHash, pkg3C, s.pgB)

	// 8) Generate user DEK
	out2, err := s.kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &s.kmsKeyID,
		KeySpec: "AES_256",
	})
	if err != nil {
		return
	}
	dekUser = out2.CiphertextBlob
	enc2, err := encryption.NewWithKey(out2.Plaintext)
	if err != nil {
		return
	}

	// 9) Encrypt pkg2||pkg4 → sBlob
	combined := append(pkg2, pkg4...)
	sBlob, err := enc2.Encrypt(combined, false)
	if err != nil {
		return
	}

	// 10) Persist file metadata
	fileID, err = s.db.CreateFileWithMeta(ownerID, filename, feaHash, dekShared, dekUser)
	if err != nil {
		return
	}

	// 11) Store & dedupe “d”
	hashD := sha256.Sum256(d)
	hexD := hex.EncodeToString(hashD[:])
	keyD := "common/" + hexD
	exists, err := s.db.ExistsChunk(hexD)
	if err != nil {
		return
	}
	if !exists {
		if err = s.store.PutObject(ctx, keyD, bytes.NewReader(d)); err != nil {
			return
		}
		if err = s.db.InsertChunk(hexD, keyD, true); err != nil {
			return
		}
	}
	if err = s.db.AddFileChunk(fileID, hexD, 0); err != nil {
		return
	}

	// 12) Store sBlob
	hashS := sha256.Sum256(sBlob)
	hexS := hex.EncodeToString(hashS[:])
	keyS := fmt.Sprintf("files/%s/s-%s", fileID, hexS)
	if err = s.store.PutObject(ctx, keyS, bytes.NewReader(sBlob)); err != nil {
		return
	}
	if err = s.db.InsertChunk(hexS, keyS, false); err != nil {
		return
	}
	if err = s.db.AddFileChunk(fileID, hexS, 1); err != nil {
		return
	}

	return
}

// Download reconstructs the original file per DSDE paper.
func (s *Service) Download(
	ctx context.Context,
	ownerID, fileID string,
) (io.ReadCloser, error) {
	// 1) Metadata + chunk infos
	meta, chunks, err := s.db.GetFileMeta(ownerID, fileID)
	if err != nil {
		return nil, err
	}
	if len(chunks) != 2 {
		return nil, fmt.Errorf("expected 2 blobs, got %d", len(chunks))
	}

	// 2) Decrypt shared DEK
	dec1, err := s.kmsClient.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: meta.DekShared,
	})
	if err != nil {
		return nil, err
	}
	enc1, err := encryption.NewWithKey(dec1.Plaintext)
	if err != nil {
		return nil, err
	}

	// 3) Fetch & collect d-data (ciphertext of pkg3C at D positions)
	dRc, err := s.store.GetObject(ctx, chunks[0].S3Key)
	if err != nil {
		return nil, err
	}
	dData, _ := io.ReadAll(dRc)
	dRc.Close()

	// 4) Decrypt user DEK
	dec2, err := s.kmsClient.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: meta.DekUser,
	})
	if err != nil {
		return nil, err
	}
	enc2, err := encryption.NewWithKey(dec2.Plaintext)
	if err != nil {
		return nil, err
	}

	// 5) Fetch & decrypt s-blob → combined = pkg2||pkg4
	sRc, err := s.store.GetObject(ctx, chunks[1].S3Key)
	if err != nil {
		return nil, err
	}
	sBlob, _ := io.ReadAll(sRc)
	sRc.Close()
	combined, err := enc2.Decrypt(sBlob)
	if err != nil {
		return nil, err
	}
	// split combined → pkg2, pkg4
	pkg4, pkg2 := split.PG(meta.FeaHash, combined, s.pgB)

	// 6) Reconstruct ciphertext pkg3C by inverse-PG on dData & pkg4
	lf := len(dData) + len(pkg4)
	// rebuild D bit‐vector for pkg3C length
	D := make([]bool, lf)
	for i := 1; i <= s.pgB; i++ {
		h := sha256.New()
		h.Write(meta.FeaHash)
		var idx [8]byte
		binary.BigEndian.PutUint64(idx[:], uint64(i))
		h.Write(idx[:])
		pos := binary.BigEndian.Uint64(h.Sum(nil)[:8]) % uint64(lf)
		D[pos] = true
	}
	// merge
	pkg3C := make([]byte, lf)
	di, p4i := 0, 0
	for j := 0; j < lf; j++ {
		if D[j] {
			pkg3C[j] = dData[di]
			di++
		} else {
			pkg3C[j] = pkg4[p4i]
			p4i++
		}
	}

	// 7) Decrypt pkg3C → pkg1
	pkg1, err := enc1.Decrypt(pkg3C)
	if err != nil {
		return nil, err
	}

	// 8) Reassemble final file F: merge pkg1 and pkg2 at original positions
	origLen := len(pkg1) + len(pkg2)
	D2 := make([]bool, origLen)
	for i := 1; i <= s.pgB; i++ {
		h := sha256.New()
		h.Write(meta.FeaHash)
		var idx [8]byte
		binary.BigEndian.PutUint64(idx[:], uint64(i))
		h.Write(idx[:])
		pos := binary.BigEndian.Uint64(h.Sum(nil)[:8]) % uint64(origLen)
		D2[pos] = true
	}
	out := make([]byte, 0, origLen)
	i1, i2 := 0, 0
	for j := 0; j < origLen; j++ {
		if D2[j] {
			out = append(out, pkg2[i2])
			i2++
		} else {
			out = append(out, pkg1[i1])
			i1++
		}
	}

	return io.NopCloser(bytes.NewReader(out)), nil
}
