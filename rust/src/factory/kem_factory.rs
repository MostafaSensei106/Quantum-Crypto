use crate::core::mlkem::{MlKemStrategy, MlKemVariant};
use crate::core::traits::KemStrategy;

pub enum KemAlgorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
}

pub struct KemFactory;

impl KemFactory {
    pub fn create_strategy(algorithm: KemAlgorithm) -> Box<dyn KemStrategy> {
        match algorithm {
            KemAlgorithm::MlKem512 => Box::new(MlKemStrategy::new(MlKemVariant::MlKem512)),
            KemAlgorithm::MlKem768 => Box::new(MlKemStrategy::new(MlKemVariant::MlKem768)),
            KemAlgorithm::MlKem1024 => Box::new(MlKemStrategy::new(MlKemVariant::MlKem1024)),
        }
    }
}
