use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use rand::{Rng, distributions::Alphanumeric, thread_rng}; // <-- Добавлен Rng и Alphanumeric
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Теперь допускаем 2 или 3 аргумента (имя программы + username [+ password])
    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: cargo run --example gen_user <username> [password]");
        eprintln!("Example (with random password): cargo run --example gen_user admin");
        eprintln!(
            "Example (with custom password): cargo run --example gen_user admin mysecretpassword"
        );
        std::process::exit(1);
    }

    let username = &args[1];

    // Базовая защита от path traversal
    if username.contains('/') || username.contains('\\') || username.is_empty() {
        eprintln!("Error: Invalid username. It must not contain slashes or be empty.");
        std::process::exit(1);
    }

    // Если пароль не указан, генерируем случайный (24 символа)
    let password = if args.len() == 3 {
        let pwd = args[2].clone();
        if pwd.is_empty() {
            eprintln!("Error: Password cannot be empty.");
            std::process::exit(1);
        }
        pwd
    } else {
        let mut rng = thread_rng();
        let random_password: String = (0..24).map(|_| rng.sample(Alphanumeric) as char).collect();
        println!("⚠️  Password not provided. Generated secure random password.");
        random_password
    };

    // Генерируем криптографически стойкую случайную соль
    let salt = SaltString::generate(&mut rand::rngs::OsRng);

    // Используем Argon2id с параметрами по умолчанию
    let argon2 = Argon2::default();

    // Хешируем пароль
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();

    // Формируем JSON-структуру
    let user_json = serde_json::json!({
        "username": username,
        "password_hash": password_hash
    });

    // Гарантируем существование директории users
    let users_dir = Path::new("users");
    if !users_dir.exists() {
        fs::create_dir_all(users_dir).expect("Failed to create users directory");
    }

    // Записываем в файл <username>.json
    let file_path = users_dir.join(format!("{}.json", username));
    fs::write(
        &file_path,
        serde_json::to_string_pretty(&user_json).expect("Failed to serialize JSON"),
    )
    .expect("Failed to write user file");

    println!("✅ User '{}' created successfully!", username);
    println!("📁 Saved to: {}", file_path.display());
    println!("🔑 Password: {}", password); // <-- Выводим пароль, чтобы пользователь мог его скопировать
    println!("🔒 Hash: {}", password_hash);
}
