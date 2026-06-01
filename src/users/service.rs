use crate::{db::Db, entities::waitlist, error::AppError};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

pub struct JoinWaitlistStruct {
    pub email: String,
}

#[derive(Clone)]
pub struct UserService {
    db: Db,
}

impl UserService {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn join_waitlist(&self, payload: JoinWaitlistStruct) -> Result<(), AppError> {
        let email = payload.email.trim().to_lowercase();

        if email.is_empty() {
            return Err(AppError::BadRequest("email is required".to_owned()));
        }

        let existing = waitlist::Entity::find()
            .filter(waitlist::Column::Email.eq(&email))
            .one(&self.db)
            .await?;

        if existing.is_some() {
            return Err(AppError::Conflict(
                "user already exists on the waitlist".to_owned(),
            ));
        }

        waitlist::ActiveModel {
            email: Set(email),
            ..Default::default()
        }
        .insert(&self.db)
        .await?;

        Ok(())
    }
}
