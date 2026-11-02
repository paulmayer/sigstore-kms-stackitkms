package stackitkms

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"
	"strconv"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stackitcloud/stackit-sdk-go/core/utils"
	kms "github.com/stackitcloud/stackit-sdk-go/services/kms/v1api"
	"github.com/stackitcloud/stackit-sdk-go/services/kms/v1api/wait"
)

const (
	defaultAlgorithm          = string(kms.ALGORITHM_ECDSA_P256_SHA256)
	defaultKeyRingDescription = "cosign keyring created by sigstore-kms-stackit"
	defaultKeyDescription     = "cosign key created by sigstore-kms-stackit"
)

var (
	ErrNotFound     = errors.New("resource not found")
	ErrAmbiguous    = errors.New("multiple matching resources found when expecting one")
	ErrInvalidInput = errors.New("unsupported or invalid input")
	ErrKeyExists    = errors.New("incompatible key exists")
)

var supportedAlgorithms = []string{
	string(kms.ALGORITHM_ECDSA_P256_SHA256),
	string(kms.ALGORITHM_ECDSA_P384_SHA384),
	string(kms.ALGORITHM_ECDSA_P521_SHA512),
}

type keyConfig struct {
	projectId   string
	regionId    string
	keyRingName string
	keyName     string
	version     int64
}

type STACKITSignerVerifier struct {
	client   *kms.APIClient
	hashFunc crypto.Hash
	config   keyConfig
}

func NewSignerVerifier(hashFunc crypto.Hash, keyResourceID string) (*STACKITSignerVerifier, error) {
	client, err := kms.NewAPIClient()
	if err != nil {
		return nil, err
	}

	parts := strings.Split(keyResourceID, "/")
	if len(parts) != 6 || !strings.EqualFold(parts[2], "keyrings") || !strings.EqualFold(parts[4], "keys") {
		return nil, fmt.Errorf("keyresourceid must be stackitkms://<projectid>/<regionid>/keyrings/<keyringname>/keys/<keyname>[:version], but received %q: %w", keyResourceID, ErrInvalidInput)
	}

	var version int64 = -1
	keyName, versionStr, found := strings.Cut(parts[5], ":")
	if found {
		version, err = strconv.ParseInt(versionStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid key version %q: %w", versionStr, err)
		}
	}

	return &STACKITSignerVerifier{
		client,
		hashFunc,
		keyConfig{
			projectId:   parts[0],
			regionId:    parts[1],
			keyRingName: parts[3],
			keyName:     keyName,
			version:     version,
		},
	}, nil
}

func filter[T any](seq iter.Seq[T], f func(T) bool) iter.Seq[T] {
	return func(yield func(T) bool) {
		for v := range seq {
			if f(v) && !yield(v) {
				return
			}
		}
	}
}

func oneOrError[T any](seq iter.Seq[T]) (T, error) {
	var (
		ret   T
		found bool
	)
	for v := range seq {
		if found {
			var zero T
			return zero, ErrAmbiguous
		}
		found, ret = true, v
	}
	if !found {
		return ret, ErrNotFound
	}
	return ret, nil
}

func (s *STACKITSignerVerifier) resolveKeyRing(ctx context.Context) (*kms.KeyRing, error) {
	keyRingList, err := s.client.DefaultAPI.ListKeyRings(ctx, s.config.projectId, s.config.regionId).Execute()
	if err != nil {
		return nil, fmt.Errorf("listing keyrings: %w", err)
	}

	keyRing, err := oneOrError(
		filter(
			slices.Values(keyRingList.KeyRings),
			func(k kms.KeyRing) bool {
				return strings.EqualFold(k.DisplayName, s.config.keyRingName)
			},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("resolving keyring %q: %w", s.config.keyRingName, err)
	}
	return &keyRing, nil
}

func (s *STACKITSignerVerifier) resolveKey(ctx context.Context, keyRingId string) (*kms.Key, error) {
	keyList, err := s.client.DefaultAPI.ListKeys(ctx, s.config.projectId, s.config.regionId, keyRingId).Execute()
	if err != nil {
		return nil, fmt.Errorf("listing keys in ring %q: %w", keyRingId, err)
	}

	key, err := oneOrError(
		filter(
			slices.Values(keyList.Keys),
			func(k kms.Key) bool {
				return strings.EqualFold(k.DisplayName, s.config.keyName)
			},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("resolving key %q in ring %q: %w", s.config.keyName, keyRingId, err)
	}
	return &key, nil
}

func (s *STACKITSignerVerifier) createKeyRing(ctx context.Context) (*kms.KeyRing, error) {
	keyRing, err := s.client.DefaultAPI.CreateKeyRing(ctx, s.config.projectId, s.config.regionId).CreateKeyRingPayload(
		kms.CreateKeyRingPayload{
			Description: utils.Ptr(defaultKeyRingDescription),
			DisplayName: s.config.keyRingName,
		},
	).Execute()
	if err != nil {
		return nil, fmt.Errorf("creating keyring with name %q: %w", s.config.keyRingName, err)
	}

	keyRing, err = wait.CreateKeyRingWaitHandler(ctx, s.client.DefaultAPI, s.config.projectId, s.config.regionId, keyRing.Id).WaitWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("waiting for creation of keyring with name %q: %w", s.config.keyRingName, err)
	}

	return keyRing, nil
}

func (s *STACKITSignerVerifier) createKey(ctx context.Context, keyRingId string, algorithm kms.Algorithm) (*kms.Key, error) {
	key, err := s.client.DefaultAPI.CreateKey(ctx, s.config.projectId, s.config.regionId, keyRingId).CreateKeyPayload(
		kms.CreateKeyPayload{
			Algorithm:   algorithm,
			Description: utils.Ptr(defaultKeyDescription),
			DisplayName: s.config.keyName,
			Purpose:     kms.PURPOSE_ASYMMETRIC_SIGN_VERIFY,
		},
	).Execute()
	if err != nil {
		return nil, fmt.Errorf("creating key with name %q: %w", s.config.keyName, err)
	}
	// Wait like in https://github.com/stackitcloud/stackit-sdk-go/blob/main/examples/kms/kms.go
	key, err = wait.CreateOrUpdateKeyWaitHandler(ctx, s.client.DefaultAPI, s.config.projectId, s.config.regionId, keyRingId, key.Id).WaitWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("waiting for creation of key with name %q: %w", s.config.keyName, err)
	}
	return key, nil
}

func (s *STACKITSignerVerifier) getLatest(ctx context.Context, keyRingId string, keyId string) (*kms.Version, error) {
	versionList, err := s.client.DefaultAPI.ListVersions(ctx, s.config.projectId, s.config.regionId, keyRingId, keyId).Execute()
	if err != nil {
		return nil, fmt.Errorf("listing versions for key %q in keyring %q: %w", keyId, keyRingId, err)
	}
	var ret *kms.Version
	var maxVersion int64 = -1
	for i := range versionList.Versions {
		if versionList.Versions[i].Number > maxVersion {
			maxVersion = versionList.Versions[i].Number
			ret = &versionList.Versions[i]
		}
	}
	if maxVersion == -1 {
		return nil, fmt.Errorf("no versions found for key %q in keyring %q: %w", keyId, keyRingId, ErrNotFound)
	}
	return ret, nil
}

func (s *STACKITSignerVerifier) getVersion(ctx context.Context, keyRingId string, keyId string, version int64) (*kms.Version, error) {
	ret, err := s.client.DefaultAPI.GetVersion(ctx, s.config.projectId, s.config.regionId, keyRingId, keyId, version).Execute()
	if err != nil {
		return nil, fmt.Errorf("getting version %q for key %q in keyring %q: %w", version, keyId, keyRingId, err)
	}
	return ret, nil
}

func (s *STACKITSignerVerifier) waitForVersion(ctx context.Context, keyRingId string, keyId string, version int64) (*kms.Version, error) {
	ret, err := wait.EnableKeyVersionWaitHandler(ctx, s.client.DefaultAPI, s.config.projectId, s.config.regionId, keyRingId, keyId, version).WaitWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("waiting for version %q: %w", version, err)
	}
	return ret, nil
}

func parsePublicKey(s string) (crypto.PublicKey, error) {
	block, rest := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no public key block")
	}
	if len(rest) > 0 {
		return nil, errors.New("multiple keys")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	return pub, nil
}

func (s STACKITSignerVerifier) DefaultAlgorithm() string {
	return defaultAlgorithm
}

func (s STACKITSignerVerifier) SupportedAlgorithms() []string {
	return supportedAlgorithms
}

func (s *STACKITSignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !slices.Contains(s.SupportedAlgorithms(), algorithm) {
		return nil, fmt.Errorf("algorithm %q not supported: %w", algorithm, ErrInvalidInput)
	}
	alg, err := kms.NewAlgorithmFromValue(algorithm)
	if err != nil {
		return nil, fmt.Errorf("algorithm %q not supported: %w", algorithm, err)
	}
	if !alg.IsValid() {
		return nil, fmt.Errorf("algorithm %q not supported: %w", algorithm, ErrInvalidInput)
	}

	if s.config.version != -1 {
		return nil, fmt.Errorf("explicit version creation not supported: %w", ErrInvalidInput)
	}

	// try to get the keyring or create a new one with the configured displayname
	keyRing, err := s.resolveKeyRing(ctx)
	createdKeyRing := false
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			keyRing, err = s.createKeyRing(ctx)
			if err != nil {
				return nil, err
			}
			createdKeyRing = true
		default:
			return nil, err
		}
	}

	// try to get the key or create a new one with the configured displayname
	var key *kms.Key
	if !createdKeyRing {
		key, err = s.resolveKey(ctx, keyRing.Id)
	}
	switch {
	case createdKeyRing, !createdKeyRing && errors.Is(err, ErrNotFound):
		key, err = s.createKey(ctx, keyRing.Id, *alg)
		if err != nil {
			return nil, fmt.Errorf("create key: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("resolve key: %w", err)
	}
	if key.Algorithm != *alg {
		return nil, fmt.Errorf("algorithm %q not supported by key %q: %w", algorithm, key.Id, ErrKeyExists)
	}

	version, err := s.getLatest(ctx, keyRing.Id, key.Id)
	version, err = s.waitForVersion(ctx, keyRing.Id, key.Id, version.Number)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(version.GetPublicKey())
}

func (s *STACKITSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.Background()
	var err error
	version := s.config.version
	versionStr := ""

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyKeyVersion(&versionStr)
	}

	if versionStr != "" {
		version, err = strconv.ParseInt(versionStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad version %q: %w", err)
		}
	}

	keyRing, err := s.resolveKeyRing(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve keyring %q: %w", s.config.keyRingName, err)
	}
	key, err := s.resolveKey(ctx, keyRing.Id)
	if err != nil {
		return nil, fmt.Errorf("resolve key %q in keyring %q: %w", s.config.keyName, s.config.keyRingName, err)
	}

	var keyVersion *kms.Version
	if version > 0 {
		keyVersion, err = s.getVersion(ctx, keyRing.Id, key.Id, version)
	} else {
		keyVersion, err = s.getLatest(ctx, keyRing.Id, key.Id)
	}
	if err != nil {
		return nil, fmt.Errorf("get key version %q: %w", version, err)
	}
	if !keyVersion.HasPublicKey() {
		return nil, fmt.Errorf("version has no public key: %w", ErrNotFound)
	}
	return parsePublicKey(keyVersion.GetPublicKey())
}

func (s *STACKITSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	panic("SignMessage() not implemented")
}

func (s *STACKITSignerVerifier) VerifySignature(signature io.Reader, message io.Reader, opts ...signature.VerifyOption) error {
	panic("VerifySignature() not implemented")
}

func (s *STACKITSignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	panic("CryptoSigner() not implemented")
}
