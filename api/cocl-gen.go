// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

package main

import (
	"io/confidentialcluster/api/v1alpha1"

	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type Args struct {
	outputDir           string
	image               string
	namespace           string
	trusteeImage        string
	pcrsComputeImage    string
	registerServerImage string
}

func main() {
	args := Args{}
	flag.StringVar(&args.outputDir, "output-dir", "config/deploy", "Output directory to save rendered YAML")
	flag.StringVar(&args.image, "image", "quay.io/confidential-clusters/cocl-operator:latest", "Container image to use in the deployment")
	flag.StringVar(&args.namespace, "namespace", "confidential-clusters", "Namespace where to install the operator")
	flag.StringVar(&args.trusteeImage, "trustee-image", "operators", "Container image with all-in-one Trustee")
	flag.StringVar(&args.pcrsComputeImage, "pcrs-compute-image", "quay.io/confidential-clusters/compute-pcrs:latest", "Container image with the cocl compute-pcrs binary")
	flag.StringVar(&args.registerServerImage, "register-server-image", "quay.io/confidential-clusters/register-server:latest", "Register server image to use in the deployment")
	flag.Parse()

	log.SetFlags(log.LstdFlags)
	if err := generateOperator(&args); err != nil {
		log.Fatalf("Failed to generate operator: %v", err)
	}
	if err := generateConfidentialClusterCR(&args); err != nil {
		log.Fatalf("Failed to generate ConfidentialCluster CR: %v", err)
	}
}

func generateOperator(args *Args) error {
	ns := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Namespace",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: args.namespace,
		},
	}
	nsYAML, err := yaml.Marshal(ns)
	if err != nil {
		return fmt.Errorf("failed to marshal namespace: %w", err)
	}

	name := "cocl-operator"
	appLabel := "cocl-operator"
	labels := map[string]string{"app": appLabel}
	replicas := int32(1)

	templateSpec := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: labels,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: name,
			Containers: []corev1.Container{
				{
					Name:    name,
					Image:   args.image,
					Command: []string{"/usr/bin/operator"},
				},
			},
		},
	}
	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: args.namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: templateSpec,
		},
	}
	operatorYAML, err := yaml.Marshal(deployment)
	if err != nil {
		return fmt.Errorf("failed to marshal deployment: %w", err)
	}

	if err := os.MkdirAll(args.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	outputPath := filepath.Join(args.outputDir, "operator.yaml")
	combinedYAML := fmt.Sprintf("%s\n---\n%s", nsYAML, operatorYAML)

	if err := os.WriteFile(outputPath, []byte(combinedYAML), 0644); err != nil {
		return fmt.Errorf("failed to write operator.yaml: %w", err)
	}

	log.Printf("Generated operator deployment and namespace at '%s'", outputPath)
	return nil
}

func generateConfidentialClusterCR(args *Args) error {
	sample := &v1alpha1.ConfidentialCluster{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "ConfidentialCluster",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "confidential-cluster",
			Namespace: args.namespace,
		},
		Spec: v1alpha1.ConfidentialClusterSpec{
			TrusteeImage:        &args.trusteeImage,
			PcrsComputeImage:    &args.pcrsComputeImage,
			RegisterServerImage: &args.registerServerImage,
			PublicTrusteeAddr:   nil,
			TrusteeKbsPort:      0,
			RegisterServerPort:  0,
		},
	}

	yamlData, err := yaml.Marshal(sample)
	if err != nil {
		return fmt.Errorf("failed to marshal ConfidentialCluster CR: %w", err)
	}

	outputPath := filepath.Join(args.outputDir, "confidential_cluster_cr.yaml")
	if err := os.WriteFile(outputPath, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write confidential_cluster_cr.yaml: %w", err)
	}

	log.Printf("Generated ConfidentialCluster CR at %s", outputPath)
	return nil
}
