use shared::Executor;

fn main() -> anyhow::Result<()> {
    let data = shared::simple_load_from_file();
    let executor = create_thread_injection::CreateThreadInjectionExecutor;
    executor.execute(data)?;
    Ok(())
}
