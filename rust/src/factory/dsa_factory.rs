use crate::core::mldsa::{MlDsaStrategy, MlDsaVariant};
use crate::core::traits::DsaStrategy;

pub enum DsaAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

pub struct DsaFactory;

impl DsaFactory {
    pub fn create_strategy(algorithm: DsaAlgorithm) -> Box<dyn DsaStrategy> {
        match algorithm {
            DsaAlgorithm::MlDsa44 => Box::new(MlDsaStrategy::new(MlDsaVariant::MlDsa44)),
            DsaAlgorithm::MlDsa65 => Box::new(MlDsaStrategy::new(MlDsaVariant::MlDsa65)),
            DsaAlgorithm::MlDsa87 => Box::new(MlDsaStrategy::new(MlDsaVariant::MlDsa87)),
        }
    }
}
