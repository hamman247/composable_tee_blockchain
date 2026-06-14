//! Ollama HTTP API client.
//!
//! Communicates with a local Ollama instance at `http://localhost:11434`.
//! Supports `/api/generate`, `/api/chat`, `/api/tags`, and `/api/show`.
//!
//! In simulator mode, responses are mocked (no real Ollama required).

use serde::{Deserialize, Serialize};

/// Default Ollama API base URL.
pub const DEFAULT_OLLAMA_URL: &str = "http://localhost:11434";

/// Ollama client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaConfig {
    /// Base URL of the Ollama API.
    pub base_url: String,
    /// Model to use by default.
    pub default_model: String,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// Whether to use simulated responses (no real Ollama needed).
    pub simulate: bool,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_OLLAMA_URL.to_string(),
            default_model: "llama3.2:1b".to_string(),
            timeout_secs: 120,
            simulate: false,
        }
    }
}

impl OllamaConfig {
    /// Config for simulation (no real Ollama).
    pub fn simulated(model: &str) -> Self {
        Self {
            default_model: model.to_string(),
            simulate: true,
            ..Default::default()
        }
    }
}

/// Request to Ollama /api/generate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateRequest {
    pub model: String,
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<GenerateOptions>,
}

/// Generation options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_predict: Option<u32>,
}

/// Response from Ollama /api/generate (non-streaming).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateResponse {
    pub model: String,
    pub response: String,
    pub done: bool,
    #[serde(default)]
    pub total_duration: u64,
    #[serde(default)]
    pub prompt_eval_count: u32,
    #[serde(default)]
    pub eval_count: u32,
}

/// Chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Request to Ollama /api/chat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<GenerateOptions>,
}

/// Response from Ollama /api/chat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub model: String,
    pub message: ChatMessage,
    pub done: bool,
    #[serde(default)]
    pub total_duration: u64,
    #[serde(default)]
    pub prompt_eval_count: u32,
    #[serde(default)]
    pub eval_count: u32,
}

/// Model info from Ollama /api/tags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub name: String,
    pub size: u64,
    pub parameter_size: Option<String>,
    pub quantization_level: Option<String>,
}

/// Ollama API client.
pub struct OllamaClient {
    config: OllamaConfig,
    #[allow(dead_code)]
    http: Option<reqwest::Client>,
}

impl OllamaClient {
    pub fn new(config: OllamaConfig) -> Self {
        let http = if !config.simulate {
            Some(
                reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(config.timeout_secs))
                    .build()
                    .expect("failed to build HTTP client"),
            )
        } else {
            None
        };

        Self { config, http }
    }

    /// Generate text from a prompt.
    pub async fn generate(
        &self,
        model: &str,
        prompt: &str,
        max_tokens: u32,
    ) -> Result<GenerateResponse, OllamaError> {
        if self.config.simulate {
            return Ok(self.simulate_generate(model, prompt, max_tokens));
        }

        let url = format!("{}/api/generate", self.config.base_url);
        let request = GenerateRequest {
            model: model.to_string(),
            prompt: prompt.to_string(),
            system: None,
            stream: false,
            options: Some(GenerateOptions {
                num_predict: Some(max_tokens),
                temperature: Some(0.7),
                top_p: Some(0.9),
                top_k: None,
            }),
        };

        let response = self
            .http
            .as_ref()
            .unwrap()
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| OllamaError::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(OllamaError::ApiError { status, body });
        }

        response
            .json::<GenerateResponse>()
            .await
            .map_err(|e| OllamaError::ParseError(e.to_string()))
    }

    /// Chat with the model.
    pub async fn chat(
        &self,
        model: &str,
        messages: Vec<ChatMessage>,
        max_tokens: u32,
    ) -> Result<ChatResponse, OllamaError> {
        if self.config.simulate {
            return Ok(self.simulate_chat(model, &messages, max_tokens));
        }

        let url = format!("{}/api/chat", self.config.base_url);
        let request = ChatRequest {
            model: model.to_string(),
            messages,
            stream: false,
            options: Some(GenerateOptions {
                num_predict: Some(max_tokens),
                temperature: Some(0.7),
                top_p: Some(0.9),
                top_k: None,
            }),
        };

        let response = self
            .http
            .as_ref()
            .unwrap()
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| OllamaError::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(OllamaError::ApiError { status, body });
        }

        response
            .json::<ChatResponse>()
            .await
            .map_err(|e| OllamaError::ParseError(e.to_string()))
    }

    /// List available models.
    pub async fn list_models(&self) -> Result<Vec<ModelInfo>, OllamaError> {
        if self.config.simulate {
            return Ok(vec![ModelInfo {
                name: self.config.default_model.clone(),
                size: 1_300_000_000,
                parameter_size: Some("1.2B".to_string()),
                quantization_level: Some("Q4_0".to_string()),
            }]);
        }

        let url = format!("{}/api/tags", self.config.base_url);
        let response = self
            .http
            .as_ref()
            .unwrap()
            .get(&url)
            .send()
            .await
            .map_err(|e| OllamaError::ConnectionFailed(e.to_string()))?;

        #[derive(Deserialize)]
        struct TagsResponse {
            models: Vec<ModelInfo>,
        }

        let tags: TagsResponse = response
            .json()
            .await
            .map_err(|e| OllamaError::ParseError(e.to_string()))?;

        Ok(tags.models)
    }

    /// Simulate a generation response (no real Ollama needed).
    fn simulate_generate(&self, model: &str, prompt: &str, _max_tokens: u32) -> GenerateResponse {
        let words: Vec<&str> = prompt.split_whitespace().collect();
        let prompt_tokens = words.len() as u32;
        let response_text = format!(
            "[Simulated {} response] This is a simulated response to: \"{}\"",
            model,
            if prompt.len() > 80 {
                &prompt[..80]
            } else {
                prompt
            }
        );
        let eval_count = response_text.split_whitespace().count() as u32;

        GenerateResponse {
            model: model.to_string(),
            response: response_text,
            done: true,
            total_duration: 150_000_000, // 150ms in nanoseconds
            prompt_eval_count: prompt_tokens,
            eval_count,
        }
    }

    fn simulate_chat(
        &self,
        model: &str,
        messages: &[ChatMessage],
        _max_tokens: u32,
    ) -> ChatResponse {
        let last_msg = messages.last().map(|m| m.content.as_str()).unwrap_or("");
        let response_text = format!(
            "[Simulated {} chat] Response to: \"{}\"",
            model,
            if last_msg.len() > 80 {
                &last_msg[..80]
            } else {
                last_msg
            }
        );
        let eval_count = response_text.split_whitespace().count() as u32;
        let prompt_tokens: u32 = messages
            .iter()
            .map(|m| m.content.split_whitespace().count() as u32)
            .sum();

        ChatResponse {
            model: model.to_string(),
            message: ChatMessage {
                role: "assistant".to_string(),
                content: response_text,
            },
            done: true,
            total_duration: 150_000_000,
            prompt_eval_count: prompt_tokens,
            eval_count,
        }
    }

    pub fn model_name(&self) -> &str {
        &self.config.default_model
    }
}

/// Ollama API errors.
#[derive(Debug)]
pub enum OllamaError {
    ConnectionFailed(String),
    ApiError { status: u16, body: String },
    ParseError(String),
}

impl std::fmt::Display for OllamaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(e) => write!(f, "Ollama connection failed: {}", e),
            Self::ApiError { status, body } => {
                write!(f, "Ollama API error {}: {}", status, body)
            }
            Self::ParseError(e) => write!(f, "Ollama response parse error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = OllamaConfig::default();
        assert_eq!(config.base_url, "http://localhost:11434");
        assert_eq!(config.default_model, "llama3.2:1b");
        assert!(!config.simulate);
    }

    #[test]
    fn test_simulated_config() {
        let config = OllamaConfig::simulated("mistral:7b");
        assert!(config.simulate);
        assert_eq!(config.default_model, "mistral:7b");
    }

    #[tokio::test]
    async fn test_simulated_generate() {
        let client = OllamaClient::new(OllamaConfig::simulated("llama3.2:1b"));
        let resp = client.generate("llama3.2:1b", "What is Rust?", 256).await.unwrap();
        assert!(resp.done);
        assert!(resp.response.contains("Simulated"));
        assert!(resp.prompt_eval_count > 0);
        assert!(resp.eval_count > 0);
    }

    #[tokio::test]
    async fn test_simulated_chat() {
        let client = OllamaClient::new(OllamaConfig::simulated("llama3.2:1b"));
        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content: "Hello!".to_string(),
        }];
        let resp = client.chat("llama3.2:1b", messages, 256).await.unwrap();
        assert!(resp.done);
        assert_eq!(resp.message.role, "assistant");
    }

    #[tokio::test]
    async fn test_simulated_list_models() {
        let client = OllamaClient::new(OllamaConfig::simulated("llama3.2:1b"));
        let models = client.list_models().await.unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].name, "llama3.2:1b");
    }

    #[test]
    fn test_request_serialization() {
        let req = GenerateRequest {
            model: "llama3.2:1b".to_string(),
            prompt: "Hello".to_string(),
            system: None,
            stream: false,
            options: Some(GenerateOptions {
                temperature: Some(0.7),
                top_p: None,
                top_k: None,
                num_predict: Some(256),
            }),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("llama3.2:1b"));
        assert!(json.contains("\"stream\":false"));
        assert!(!json.contains("top_p")); // skip_serializing_if
    }
}
