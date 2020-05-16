use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::errors::Error;
use uuid::Uuid;

#[derive(serde::Serialize, Debug)]
pub struct Token {
    token: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[repr(C)]
pub struct Jwt {
    /// Issuer (journali.nl)
    iss: String,

    exp: DateTime<Utc>,

    /// subject
    sub: Uuid,
}

fn get_secret() -> String {
    "SUPER SECRET".into()
}

impl Jwt {
    pub fn new(iss: String, duration: Duration, sub: Uuid) -> Self {
        let now = Utc::now();
        let exp = now + duration;

        Self { iss, exp: exp, sub }
    }

    pub fn sub(&self) -> Uuid {
        self.sub
    }

    pub fn tokenize(self) -> Token {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = get_secret();
        let token = encode(
            &Header::default(),
            &self,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        Token { token }
    }

    pub fn detokenize(jwt: &str) -> Result<Jwt, Error> {
        use jsonwebtoken::{decode, DecodingKey, Validation};

        let secret = get_secret();

        let validation = Validation::default();
        decode::<Jwt>(
            jwt,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map(|token| token.claims)
    }
}

fn main() {
    let uuid = Uuid::new_v4();
    dbg!(&uuid);

    let jwt = Jwt::new("my.domain".into(), Duration::days(30), uuid);
    dbg!(&jwt);

    let jwt_token = jwt.tokenize();
    dbg!(&jwt_token);

    let Token { token } = jwt_token;
    let detokenized = Jwt::detokenize(&token).unwrap();

    dbg!(detokenized.sub);
}
