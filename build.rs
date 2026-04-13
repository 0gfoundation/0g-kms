fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile inter-node KMS cluster proto
    tonic_build::compile_protos("proto/kms_cluster.proto")?;
    // Compile tapp-service proto (for GetAppSecretKey in tee.rs)
    tonic_build::compile_protos("proto/tapp_service.proto")?;
    Ok(())
}
