package registry

import "testing"

func TestCodexPlanModelsIncludeCurrentCMSGModels(t *testing.T) {
	tests := []struct {
		name     string
		models   []*ModelInfo
		required []string
	}{
		{name: "free", models: GetCodexFreeModels(), required: []string{"gpt-5.6-terra", "gpt-5.6-luna"}},
		{name: "plus", models: GetCodexPlusModels(), required: []string{"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"}},
		{name: "team", models: GetCodexTeamModels(), required: []string{"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"}},
		{name: "pro", models: GetCodexProModels(), required: []string{"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, modelID := range test.required {
				if !containsModelID(test.models, modelID) {
					t.Fatalf("model catalog does not include %q", modelID)
				}
			}
		})
	}

	if containsModelID(GetCodexFreeModels(), "gpt-5.6-sol") {
		t.Fatal("free plan unexpectedly includes gpt-5.6-sol")
	}
}

func containsModelID(models []*ModelInfo, modelID string) bool {
	for _, model := range models {
		if model != nil && model.ID == modelID {
			return true
		}
	}
	return false
}
