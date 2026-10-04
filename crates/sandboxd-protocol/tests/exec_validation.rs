use sandboxd_protocol::ExecId;
use sandboxd_protocol::exec::{ExecutionSpec, OutputPolicy, StdinMode};
use std::collections::BTreeMap;

#[test]
fn image_defaults_accept_empty_argv_without_panicking_but_reject_empty_executable() {
    let mut spec = ExecutionSpec {
        id: ExecId::new("image-defaults").unwrap(),
        argv: Vec::new(),
        use_image_defaults: true,
        cwd: "/".into(),
        uid: 0,
        gid: 0,
        environment: BTreeMap::new(),
        secret_environment: BTreeMap::new(),
        pty: None,
        stdin: StdinMode::Closed,
        timeout_ms: 1000,
        detached: false,
        output_policy: OutputPolicy::Disabled,
    };
    assert!(spec.validate().is_ok());
    spec.use_image_defaults = false;
    assert!(spec.validate().is_err());
    spec.use_image_defaults = true;
    spec.argv = vec![String::new()];
    assert!(spec.validate().is_err());
    spec.argv = vec!["/bin/true".into()];
    assert!(spec.validate().is_ok());
}
