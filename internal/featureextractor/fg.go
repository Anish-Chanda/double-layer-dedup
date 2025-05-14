package featureextractor

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/aclements/go-rabin/rabin"
)

// FGConfig holds parameters for FG(F) extraction.
type FGConfig struct {
	NumFingerprints      int                   // N: target number of Rabin fingerprints (P_i) to extract
	RabinWindowSize      int                   // Window size for Rabin hasher (e.g., 64 as per paper)
	RabinPolynomial      uint64                // The specific Rabin polynomial (e.g., rabin.Poly64)
	RabinTargetBits      int                   // For cut condition (e.g. 13 for ~8KB avg chunks if mask is (1<<bits)-1)
	RabinCutValue        uint64                // The value to compare (fingerprint & mask) against.
	LinearFunctionCoeffs []LinearFunctionCoeff // Should have N elements
}

// LinearFunctionCoeff holds coefficients for one linear function πi(x) = (a*x + m) mod 2^64
type LinearFunctionCoeff struct {
	A uint64 // Coefficient a_i
	M uint64 // Coefficient m_i
}

// FGExtractor is responsible for generating FG(F).
type FGExtractor struct {
	config        FGConfig
	hashAlgorithm func() hash.Hash // e.g., sha256.New for the final hash
	rabinTable    *rabin.Table     // Store the precomputed table
}

// NewFGExtractor creates a new FG(F) extractor.
// config.LinearFunctionCoeffs must have N = config.NumFingerprints elements.
func NewFGExtractor(config FGConfig) (*FGExtractor, error) {
	if len(config.LinearFunctionCoeffs) != config.NumFingerprints {
		return nil, fmt.Errorf("number of linear coefficients (%d) must match NumFingerprints (%d)", len(config.LinearFunctionCoeffs), config.NumFingerprints)
	}
	if config.NumFingerprints <= 0 {
		return nil, fmt.Errorf("NumFingerprints must be positive")
	}
	if config.RabinWindowSize <= 0 {
		return nil, fmt.Errorf("RabinWindowSize must be positive")
	}
	if config.RabinPolynomial == 0 {
		return nil, fmt.Errorf("RabinPolynomial must be specified (e.g., rabin.Poly64)")
	}
	if config.RabinTargetBits <= 0 || config.RabinTargetBits >= 64 { // TargetBits define the mask width
		return nil, fmt.Errorf("RabinTargetBits must be between 1 and 63")
	}

	table := rabin.NewTable(config.RabinPolynomial, config.RabinWindowSize)

	return &FGExtractor{
		config:        config,
		hashAlgorithm: sha256.New,
		rabinTable:    table,
	}, nil
}

func (e *FGExtractor) extractNRabinFingerprints(f io.Reader) ([]uint64, error) {
	fingerprints := make([]uint64, 0, e.config.NumFingerprints)

	// CORRECTED: Use the top-level rabin.New function, passing the precomputed table
	hasher := rabin.New(e.rabinTable)

	mask := uint64((1 << e.config.RabinTargetBits) - 1)
	cutValue := e.config.RabinCutValue & mask

	buf := make([]byte, 4096)
	var totalBytesFedToHasher uint64

	// ... (rest of the extractNRabinFingerprints logic remains IDENTICAL to the previous correct version) ...
	// Loop for reading, hasher.Write, hasher.Sum64, cut condition check, EOF handling...
	// This logic was okay.
	for {
		// Stop if we've already collected enough fingerprints
		if len(fingerprints) >= e.config.NumFingerprints {
			break
		}

		n, readErr := f.Read(buf)
		if n > 0 {
			_, _ = hasher.Write(buf[:n]) // According to docs, error is always nil
			totalBytesFedToHasher += uint64(n)

			if totalBytesFedToHasher >= uint64(e.config.RabinWindowSize) || (readErr == io.EOF && totalBytesFedToHasher > 0) {
				currentFP := hasher.Sum64()
				if (currentFP & mask) == cutValue {
					isNewDistinctFP := true
					if len(fingerprints) > 0 && fingerprints[len(fingerprints)-1] == currentFP {
						isNewDistinctFP = false
					}
					if isNewDistinctFP {
						fingerprints = append(fingerprints, currentFP)
						if len(fingerprints) >= e.config.NumFingerprints {
							break
						}
					}
				}
			}
		}

		if readErr == io.EOF {
			if totalBytesFedToHasher > 0 && len(fingerprints) < e.config.NumFingerprints {
				finalFP := hasher.Sum64()
				isNewDistinctFP := true
				if len(fingerprints) > 0 && fingerprints[len(fingerprints)-1] == finalFP {
					isNewDistinctFP = false
				}
				if isNewDistinctFP || len(fingerprints) == 0 {
					fingerprints = append(fingerprints, finalFP)
				}
			}
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("error reading file for fingerprinting: %w", readErr)
		}
	}
	return e.finalizeFingerprints(fingerprints)
}

// finalizeFingerprints ensures we have exactly N fingerprints, padding or truncating if necessary.
func (e *FGExtractor) finalizeFingerprints(fps []uint64) ([]uint64, error) {
	targetN := e.config.NumFingerprints
	currentN := len(fps)

	if currentN == targetN {
		return fps, nil
	}

	if currentN == 0 {
		// No fingerprints extracted (e.g., empty file).
		// Return N zero fingerprints for consistency.
		if targetN > 0 {
			return make([]uint64, targetN), nil
		}
		return []uint64{}, nil // N=0, empty fps.
	}

	// currentN > 0
	if currentN > targetN {
		// Too many fingerprints found: take the first N.
		return fps[:targetN], nil
	}

	// currentN < targetN (and currentN > 0)
	// Too few fingerprints: pad with the last known fingerprint.
	paddedFps := make([]uint64, targetN)
	copy(paddedFps, fps) // Copy the ones we have
	lastKnownFp := fps[currentN-1]
	for i := currentN; i < targetN; i++ {
		paddedFps[i] = lastKnownFp // Pad
	}
	return paddedFps, nil
}

// applyLinearFunction calculates Si = (a_i * P_i + m_i) mod 2^64
func (e *FGExtractor) applyLinearFunction(p_i uint64, coeff LinearFunctionCoeff) uint64 {
	term1 := coeff.A * p_i
	s_i := term1 + coeff.M
	return s_i
}

// GenerateFeatureFG executes the FG(F) generation process.
// F is the file reader.
func (e *FGExtractor) GenerateFeatureFG(f io.Reader) (fea []byte, err error) {
	rabinPrints, err := e.extractNRabinFingerprints(f)
	if err != nil {
		// This path should ideally not be hit if finalizeFingerprints handles all cases
		// by returning a valid (possibly padded or zeroed) slice or a more specific error.
		return nil, fmt.Errorf("failed to extract/finalize Rabin fingerprints: %w", err)
	}

	if len(rabinPrints) != e.config.NumFingerprints {
		// This check should be redundant if finalizeFingerprints guarantees the length.
		return nil, fmt.Errorf("internal error: expected %d Rabin fingerprints after finalization, got %d", e.config.NumFingerprints, len(rabinPrints))
	}

	subFeaturesS := make([][]byte, e.config.NumFingerprints)
	for i := 0; i < e.config.NumFingerprints; i++ {
		s_i_val := e.applyLinearFunction(rabinPrints[i], e.config.LinearFunctionCoeffs[i])
		s_i_bytes := make([]byte, 8)
		binary.BigEndian.PutUint64(s_i_bytes, s_i_val)
		subFeaturesS[i] = s_i_bytes
	}

	finalHasher := e.hashAlgorithm()
	for _, s_bytes := range subFeaturesS {
		_, err := finalHasher.Write(s_bytes) // Error from hash.Hash.Write is typically for specific hasher issues
		if err != nil {
			return nil, fmt.Errorf("failed to write sub-feature to final hasher: %w", err)
		}
	}

	fea = finalHasher.Sum(nil)
	return fea, nil
}
