wit_bindgen::generate!({
    path: "../../interfaces",
    world: "bioworld:plugin/bioworld-plugin@2.0.0",
    additional_derives: [PartialEq, Eq, Clone],
});

pub use bioworld::plugin::evidence::ArtifactRef;

#[cfg(test)]
mod tests {
    use super::{
        ArtifactRef, Guest,
        bioworld::plugin::{annotations, evidence},
    };

    struct ContractProbe;

    impl Guest for ContractProbe {
        fn run(input: String) -> Result<String, String> {
            Ok(input)
        }
    }

    #[test]
    fn generated_world_preserves_expected_function_signatures() {
        let _: fn(&str) -> Vec<ArtifactRef> = evidence::list_scoped_artifacts;
        let _: fn(&str, &str) -> Result<String, String> = annotations::write_draft;
        let _: fn(String) -> Result<String, String> = ContractProbe::run;
    }
}
