use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Видимость репозитория
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
}

impl Visibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Private => "private",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "public" => Some(Visibility::Public),
            "private" => Some(Visibility::Private),
            _ => None,
        }
    }
}

/// Метаданные репозитория (хранятся в `.repo-config` в корне репозитория)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryMetadata {
    pub visibility: Visibility,
    #[serde(default)]
    pub collaborators: Vec<String>,
}

impl Default for RepositoryMetadata {
    fn default() -> Self {
        Self {
            visibility: Visibility::Public,
            collaborators: Vec::new(),
        }
    }
}

/// Менеджер метаданных репозиториев (файловое хранилище)
pub struct RepositoryMetadataManager {
    repos_base: PathBuf,
}

impl RepositoryMetadataManager {
    pub fn new(repos_base: PathBuf) -> Self {
        RepositoryMetadataManager { repos_base }
    }

    /// Путь к файлу конфигурации репозитория
    fn config_path(&self, owner: &str, repo: &str) -> PathBuf {
        self.repos_base.join(owner).join(repo).join(".repo-config")
    }

    /// Загрузить метаданные репозитория
    fn load_metadata(config_path: &Path) -> anyhow::Result<RepositoryMetadata> {
        if config_path.exists() {
            let content = std::fs::read_to_string(config_path)?;
            let meta: RepositoryMetadata = toml::from_str(&content)?;
            Ok(meta)
        } else {
            Ok(RepositoryMetadata::default())
        }
    }

    /// Сохранить метаданные репозитория
    fn save_metadata(config_path: &Path, metadata: &RepositoryMetadata) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(metadata)?;
        std::fs::write(config_path, content)?;
        Ok(())
    }

    /// Получить метаданные репозитория
    pub fn get_metadata(&self, owner: &str, repo: &str) -> anyhow::Result<RepositoryMetadata> {
        let config_path = self.config_path(owner, repo);
        Self::load_metadata(&config_path)
    }

    /// Установить видимость репозитория
    pub fn set_visibility(
        &self,
        owner: &str,
        repo: &str,
        visibility: Visibility,
    ) -> anyhow::Result<()> {
        let config_path = self.config_path(owner, repo);
        let mut metadata = Self::load_metadata(&config_path)?;
        metadata.visibility = visibility;
        Self::save_metadata(&config_path, &metadata)?;
        Ok(())
    }

    /// Проверить, имеет ли пользователь доступ к репозиторию (чтение)
    pub fn can_access(&self, owner: &str, repo: &str, user: Option<&str>) -> anyhow::Result<bool> {
        let metadata = self.get_metadata(owner, repo)?;

        // Если репозиторий публичный, все могут читать
        if metadata.visibility == Visibility::Public {
            return Ok(true);
        }

        // Если приватный, только владелец и коллаборанты могут читать
        if let Some(username) = user {
            // Владелец всегда имеет доступ
            if username == owner {
                return Ok(true);
            }

            // Проверяем, является ли пользователь коллаборантом
            return Ok(metadata.collaborators.iter().any(|c| c == username));
        }

        // Анонимный пользователь не имеет доступа к приватным репозиториям
        Ok(false)
    }

    /// Добавить коллаборатора
    pub fn add_collaborator(&self, owner: &str, repo: &str, collaborator: &str) -> anyhow::Result<()> {
        let config_path = self.config_path(owner, repo);
        let mut metadata = Self::load_metadata(&config_path)?;
        
        if !metadata.collaborators.contains(&collaborator.to_string()) {
            metadata.collaborators.push(collaborator.to_string());
        }
        
        Self::save_metadata(&config_path, &metadata)?;
        Ok(())
    }

    /// Удалить коллаборатора
    pub fn remove_collaborator(&self, owner: &str, repo: &str, collaborator: &str) -> anyhow::Result<()> {
        let config_path = self.config_path(owner, repo);
        let mut metadata = Self::load_metadata(&config_path)?;
        metadata.collaborators.retain(|c| c != collaborator);
        Self::save_metadata(&config_path, &metadata)?;
        Ok(())
    }

    /// Получить список коллаборторов
    pub fn get_collaborators(&self, owner: &str, repo: &str) -> anyhow::Result<Vec<String>> {
        let metadata = self.get_metadata(owner, repo)?;
        Ok(metadata.collaborators)
    }
}
