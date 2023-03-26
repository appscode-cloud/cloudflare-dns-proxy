/*
Copyright AppsCode Inc. and Contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"encoding/json"
	"net/http"

	api "go.bytebuilders.dev/installer/apis/installer/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type InstallerMetadata struct {
	ID string `json:"ID"`

	DeploymentType       api.DeploymentType `json:"deploymentType"`
	RequestedDomain      string             `json:"requestedDomain"`
	HostedDomain         string             `json:"hostedDomain,omitempty"`
	OwnerID              int64              `json:"-"`
	OwnerName            string             `json:"ownerName"`
	RequesterID          int64              `json:"-"`
	RequesterDisplayName string             `json:"requesterDisplayName,omitempty"`
	RequesterUsername    string             `json:"requesterUsername,omitempty"`
	AdminDisplayName     string             `json:"adminDisplayName"`
	AdminEmail           string             `json:"adminEmail"`
	ClusterID            string             `json:"clusterID"`

	CreateTimestamp metav1.Time `json:"createTimestamp"`
	ExpiryTimestamp metav1.Time `json:"expiryTimestamp,omitempty"`
}

func GetInstallerMetadata(url, authHeader string) (*InstallerMetadata, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", authHeader)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	var result InstallerMetadata
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
