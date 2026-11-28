// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"sync"

	"k8s.io/kms/pkg/service"
)

// Service is the KMS v2 service, on k8s.io/kms's own gRPC server, over a keyring
// Reload can replace when the keyring rotates.
type Service struct {
	mutex sync.RWMutex
	ring  *Keyring
}

// NewService serves ring.
func NewService(ring *Keyring) *Service { return &Service{ring: ring} }

// Reload makes ring the one served.
func (s *Service) Reload(ring *Keyring) {
	s.mutex.Lock()
	s.ring = ring
	s.mutex.Unlock()
}

func (s *Service) keyring() *Keyring {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.ring
}

func (s *Service) Status(context.Context) (*service.StatusResponse, error) {
	return &service.StatusResponse{Version: "v2", Healthz: "ok", KeyID: s.keyring().ActiveID()}, nil
}

func (s *Service) Encrypt(_ context.Context, _ string, plaintext []byte) (*service.EncryptResponse, error) {
	ciphertext, id, err := s.keyring().Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return &service.EncryptResponse{Ciphertext: ciphertext, KeyID: id}, nil
}

func (s *Service) Decrypt(_ context.Context, _ string, request *service.DecryptRequest) ([]byte, error) {
	return s.keyring().Decrypt(request.Ciphertext, request.KeyID)
}
