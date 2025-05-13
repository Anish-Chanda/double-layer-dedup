package featureextractor

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/aclements/go-rabin/rabin"
)

func getDefaultTestFGConfig(numFingerprints int) (FGConfig, error) {
	if numFingerprints <= 0 {
		numFingerprints = 3 // Default for tests
	}
	coeffs := make([]LinearFunctionCoeff, numFingerprints)
	for i := 0; i < numFingerprints; i++ {
		coeffs[i] = LinearFunctionCoeff{A: uint64(1001 + i*13), M: uint64(2003 + i*17)}
	}
	return FGConfig{
		NumFingerprints:      numFingerprints,
		RabinWindowSize:      64,
		RabinPolynomial:      rabin.Poly64, // Use the library's defined constant
		RabinTargetBits:      10,           // e.g., mask will be 0x3FF
		RabinCutValue:        0,            // Cut when (fingerprint & 0x3FF) == 0
		LinearFunctionCoeffs: coeffs,
	}, nil
}

func TestNewFGExtractor(t *testing.T) {
	cfg, _ := getDefaultTestFGConfig(3)
	_, err := NewFGExtractor(cfg)
	if err != nil {
		t.Fatalf("NewFGExtractor() error = %v, wantErr %v", err, false)
	}

	// Test various failure conditions for NewFGExtractor
	testCases := []struct {
		name        string
		modifier    func(c *FGConfig)
		expectError bool
	}{
		{"mismatched coeffs", func(c *FGConfig) { c.LinearFunctionCoeffs = c.LinearFunctionCoeffs[:1] }, true},
		{"zero NumFingerprints", func(c *FGConfig) { c.NumFingerprints = 0 }, true},
		{"zero RabinWindowSize", func(c *FGConfig) { c.RabinWindowSize = 0 }, true},
		{"zero RabinPolynomial", func(c *FGConfig) { c.RabinPolynomial = 0 }, true},
		{"zero RabinTargetBits", func(c *FGConfig) { c.RabinTargetBits = 0 }, true},
		{"RabinTargetBits too large", func(c *FGConfig) { c.RabinTargetBits = 64 }, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfgCopy, _ := getDefaultTestFGConfig(3)
			tc.modifier(&cfgCopy)
			_, err := NewFGExtractor(cfgCopy)
			if (err != nil) != tc.expectError {
				t.Errorf("NewFGExtractor() error = %v, expectError %v", err, tc.expectError)
			}
		})
	}
}

func TestGenerateFeatureFG_Determinism(t *testing.T) {
	cfg, _ := getDefaultTestFGConfig(5)
	extractor, _ := NewFGExtractor(cfg)

	data := make([]byte, 20*1024) // 20KB of random data
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	reader1 := bytes.NewReader(data)
	fea1, err := extractor.GenerateFeatureFG(reader1)
	if err != nil {
		t.Fatalf("GenerateFeatureFG() failed for reader1: %v", err)
	}
	if len(fea1) == 0 {
		t.Error("GenerateFeatureFG() returned empty fea1")
	}

	reader2 := bytes.NewReader(data)
	fea2, err := extractor.GenerateFeatureFG(reader2)
	if err != nil {
		t.Fatalf("GenerateFeatureFG() failed for reader2: %v", err)
	}
	if !bytes.Equal(fea1, fea2) {
		t.Errorf("GenerateFeatureFG() is not deterministic.\nfea1: %x\nfea2: %x", fea1, fea2)
	}
}

func TestGenerateFeatureFG_DifferentDataProducesDifferentFea(t *testing.T) {
	cfg, _ := getDefaultTestFGConfig(3)
	extractor, _ := NewFGExtractor(cfg)

	data1 := make([]byte, 5*1024)
	if _, err := rand.Read(data1); err != nil {
		t.Fatalf("Failed to generate random data1: %v", err)
	}

	data2 := make([]byte, 5*1024)
	// Ensure data2 is different from data1
	for {
		if _, err := rand.Read(data2); err != nil {
			t.Fatalf("Failed to generate random data2: %v", err)
		}
		if !bytes.Equal(data1, data2) {
			break
		}
	}

	reader1 := bytes.NewReader(data1)
	fea1, err := extractor.GenerateFeatureFG(reader1)
	if err != nil {
		t.Fatalf("GenerateFeatureFG() failed for data1: %v", err)
	}

	reader2 := bytes.NewReader(data2)
	fea2, err := extractor.GenerateFeatureFG(reader2)
	if err != nil {
		t.Fatalf("GenerateFeatureFG() failed for data2: %v", err)
	}

	if bytes.Equal(fea1, fea2) && len(data1) > 0 { // only fail if non-empty data produced same fea
		t.Errorf("GenerateFeatureFG() produced same fea for different data.\nfea1: %x\nfea2: %x", fea1, fea2)
	}
}

func TestGenerateFeatureFG_SmallFileHandling(t *testing.T) {
	cfg, _ := getDefaultTestFGConfig(3) // N=3
	extractor, _ := NewFGExtractor(cfg)

	// Case 1: File smaller than window size
	smallData1 := "very_short_data" // length < windowSize (64)
	readerS1 := strings.NewReader(smallData1)
	fea_s1, err := extractor.GenerateFeatureFG(readerS1)
	if err != nil {
		t.Fatalf("GenerateFeatureFG() for file smaller than window failed: %v", err)
	}
	if len(fea_s1) == 0 {
		t.Error("GenerateFeatureFG() for small file (less than window) returned empty fea")
	}
	t.Logf("fea (file < window, N=3): %x", fea_s1)

	readerS1Again := strings.NewReader(smallData1)
	fea_s1_again, _ := extractor.GenerateFeatureFG(readerS1Again)
	if !bytes.Equal(fea_s1, fea_s1_again) {
		t.Errorf("Small file fea not deterministic. Expected %x, got %x", fea_s1, fea_s1_again)
	}

	// Case 2: File slightly larger than window, might not trigger N distinct cuts
	mediumData := strings.Repeat("Z", 100) // 100 bytes
	readerM1 := strings.NewReader(mediumData)
	fea_m1, err := extractor.GenerateFeatureFG(readerM1)
	if err != nil {
		t.Fatalf("GenerateFeatureFG() for medium file failed: %v", err)
	}
	if len(fea_m1) == 0 {
		t.Error("GenerateFeatureFG() for medium file returned empty fea")
	}
	t.Logf("fea (medium file, N=3): %x", fea_m1)
}

func TestGenerateFeatureFG_EmptyFile(t *testing.T) {
	cfg, _ := getDefaultTestFGConfig(3) // N=3
	extractor, _ := NewFGExtractor(cfg)

	emptyDataReader := strings.NewReader("")
	fea, err := extractor.GenerateFeatureFG(emptyDataReader)
	if err != nil {
		t.Fatalf("GenerateFeatureFG() for empty file failed: %v", err)
	}

	// Expected fea for empty file (N=3, all Pi=0 due to finalizeFingerprints policy)
	// Linear coeffs for N=3 (from getDefaultTestFGConfig):
	// C0: A=1001, M=2003 => S0 = (1001*0 + 2003) = 2003
	// C1: A=1014, M=2020 => S1 = (1014*0 + 2020) = 2020
	// C2: A=1027, M=2037 => S2 = (1027*0 + 2037) = 2037
	sTransformedZeros := make([][]byte, 3)
	sTransformedZeros[0] = make([]byte, 8)
	binary.BigEndian.PutUint64(sTransformedZeros[0], cfg.LinearFunctionCoeffs[0].M) // P_i=0
	sTransformedZeros[1] = make([]byte, 8)
	binary.BigEndian.PutUint64(sTransformedZeros[1], cfg.LinearFunctionCoeffs[1].M) // P_i=0
	sTransformedZeros[2] = make([]byte, 8)
	binary.BigEndian.PutUint64(sTransformedZeros[2], cfg.LinearFunctionCoeffs[2].M) // P_i=0

	finalHasher := sha256.New()
	for _, sb := range sTransformedZeros {
		finalHasher.Write(sb)
	}
	expectedEmptyFea := finalHasher.Sum(nil)

	if !bytes.Equal(fea, expectedEmptyFea) {
		t.Errorf("GenerateFeatureFG() for empty file: \nexpected %x (hash of N transformed zeros)\ngot      %x", expectedEmptyFea, fea)
	}
	t.Logf("fea (empty file, N=3): %x", fea)
}

func TestExtractNRabinFingerprints_PaddingAndTruncation(t *testing.T) {
	// Config to make it easy to get MORE than N fingerprints (for truncation test)
	cfgMoreCuts, _ := getDefaultTestFGConfig(3)
	cfgMoreCuts.RabinTargetBits = 2 // Very frequent cuts (mask 0b11)
	cfgMoreCuts.RabinCutValue = 0   // Cut if lower 2 bits are 0
	extractorMore, _ := NewFGExtractor(cfgMoreCuts)

	// Data designed to hit the cut condition (X & 0b11) == 0 frequently
	lotsOfCutsData := make([]byte, 1024)
	for i := range lotsOfCutsData {
		lotsOfCutsData[i] = byte(i)
	} // Some variance, will hit pattern

	printsMore, err := extractorMore.extractNRabinFingerprints(bytes.NewReader(lotsOfCutsData))
	if err != nil {
		t.Fatalf("extractNRabinFingerprints with frequent cuts failed: %v", err)
	}
	if len(printsMore) != cfgMoreCuts.NumFingerprints {
		t.Errorf("Expected %d prints (truncation), got %d", cfgMoreCuts.NumFingerprints, len(printsMore))
	}

	// Config to make it hard to get N fingerprints (for padding test)
	cfgLessCuts, _ := getDefaultTestFGConfig(5) // Expect 5 FPs
	cfgLessCuts.RabinTargetBits = 16            // Infrequent cuts (mask has many bits)
	cfgLessCuts.RabinCutValue = (1 << 15) + 1   // A specific, less common pattern
	extractorLess, _ := NewFGExtractor(cfgLessCuts)

	lessCutsData := make([]byte, 512) // 0.5KB of random data
	if _, err := rand.Read(lessCutsData); err != nil {
		t.Fatalf("Failed to gen random data for less cuts: %v", err)
	}

	printsLess, err := extractorLess.extractNRabinFingerprints(bytes.NewReader(lessCutsData))
	if err != nil {
		t.Fatalf("extractNRabinFingerprints with infrequent cuts failed: %v", err)
	}
	if len(printsLess) != cfgLessCuts.NumFingerprints {
		t.Errorf("Expected %d prints (padding), got %d", cfgLessCuts.NumFingerprints, len(printsLess))
	}

	// Check if padding occurred (last few elements might be identical if original FPs < N)
	// Only meaningful if at least one FP was found before padding.
	numOriginalFPsFound := 0
	if len(printsLess) > 0 {
		lastUniqueFp := printsLess[0]
		numOriginalFPsFound = 1
		for i := 1; i < len(printsLess); i++ {
			if printsLess[i] != lastUniqueFp {
				numOriginalFPsFound++
				lastUniqueFp = printsLess[i]
			} else {
				// This means padding started here or earlier
				break
			}
		}
	}

	if numOriginalFPsFound > 0 && numOriginalFPsFound < cfgLessCuts.NumFingerprints {
		t.Logf("Padding occurred for infrequent cuts as expected. Original FPs found: %d, Target N: %d", numOriginalFPsFound, cfgLessCuts.NumFingerprints)
		if printsLess[cfgLessCuts.NumFingerprints-1] != printsLess[numOriginalFPsFound-1] {
			t.Errorf("Padding value is incorrect. Expected padding with %x, but last element is %x", printsLess[numOriginalFPsFound-1], printsLess[cfgLessCuts.NumFingerprints-1])
		}
	} else if numOriginalFPsFound == cfgLessCuts.NumFingerprints {
		t.Logf("Infrequent cuts test still found N distinct fingerprints.")
	} else if numOriginalFPsFound == 0 && cfgLessCuts.NumFingerprints > 0 {
		// All should be 0 if no FPs were found initially before padding
		isAllZeros := true
		for _, fp := range printsLess {
			if fp != 0 {
				isAllZeros = false
				break
			}
		}
		if !isAllZeros {
			t.Errorf("Expected all zero FPs due to no original FPs found before padding, but got: %v", printsLess)
		} else {
			t.Logf("Padding with zeros occurred as no original FPs found.")
		}
	}
}
