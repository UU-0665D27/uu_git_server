use async_trait::async_trait;
use sqlx::SqlitePool;
use tower_sessions::{
    SessionStore,
    cookie::time,
    session::{Id, Record},
    session_store,
};

#[derive(Clone, Debug)]
pub struct SqliteSessionStore {
    pool: SqlitePool,
}

impl SqliteSessionStore {
    pub async fn new(pool: SqlitePool) -> Result<Self, sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY NOT NULL,
                data BLOB NOT NULL,
                expiry_date INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl SessionStore for SqliteSessionStore {
    async fn save(&self, record: &Record) -> session_store::Result<()> {
        let data =
            rmp_serde::to_vec(record).map_err(|e| session_store::Error::Encode(e.to_string()))?;
        sqlx::query(
            "INSERT INTO sessions (id, data, expiry_date) VALUES (?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET data = excluded.data, expiry_date = excluded.expiry_date",
        )
        .bind(record.id.to_string())
        .bind(data)
        .bind(record.expiry_date.unix_timestamp())
        .execute(&self.pool)
        .await
        .map_err(|e| session_store::Error::Backend(e.to_string()))?;
        Ok(())
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT data FROM sessions WHERE id = ? AND expiry_date > ?")
                .bind(session_id.to_string())
                .bind(time::OffsetDateTime::now_utc().unix_timestamp())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| session_store::Error::Backend(e.to_string()))?;

        row.map(|(data,)| {
            rmp_serde::from_slice(&data).map_err(|e| session_store::Error::Decode(e.to_string()))
        })
        .transpose()
    }

    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(session_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| session_store::Error::Backend(e.to_string()))?;
        Ok(())
    }
}
