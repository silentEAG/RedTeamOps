use shared::Executor;

fn main() -> anyhow::Result<()> {
    let data = shared::simple_load_from_file();
    let executor = callback_injection::CallbackInjectionExecutor {
        callback_type: callback_injection::CallbackType::EnumFontFamiliesExA,
    };
    executor.execute(data)?;
    Ok(())
}
