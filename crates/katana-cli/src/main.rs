mod flags;
mod output;

use clap::Parser;
use flags::CliArgs;
use katana_core::options::Options;
use katana_engine::{Engine, HeadlessEngine, HybridEngine, StandardEngine};
use output::OutputWriter;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(log_level))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut target_urls = Vec::new();
    if let Some(u) = args.url {
        target_urls.push(u);
    } else if let Some(list_path) = args.list {
        let file = File::open(list_path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line_str = line?.trim().to_string();
            if !line_str.is_empty() {
                target_urls.push(line_str);
            }
        }
    } else {
        // Read from stdin if available
        let stdin = io::stdin();
        let reader = stdin.lock();
        for line in reader.lines() {
            let line_str = line?.trim().to_string();
            if !line_str.is_empty() {
                target_urls.push(line_str);
            }
        }
    }

    if target_urls.is_empty() {
        eprintln!("Error: No target URLs provided. Use -u <url> or -l <file>");
        std::process::exit(1);
    }

    let options = Options {
        urls: target_urls.clone(),
        max_depth: args.depth,
        concurrency: args.concurrency,
        timeout: args.timeout,
        delay: args.delay,
        headless: args.headless,
        headless_hybrid: args.headless_hybrid,
        system_chrome: args.system_chrome,
        chrome_ws_url: args.chrome_ws_url,
        chrome_data_dir: args.chrome_data_dir,
        automatic_form_fill: args.automatic_form_fill,
        scrape_js: args.js_crawl,
        scrape_jsluice: args.jsluice,
        form_extraction: args.form_extraction,
        ignore_query_params: args.ignore_query_params,
        filter_similar: args.filter_similar,
        path_climb: args.path_climb,
        max_domain_pages: args.max_domain_pages,
        display_out_scope: args.display_out_scope,
        proxy: args.proxy,
        scan_secrets: args.scan_secrets,
        output_file: args.output.clone(),
        store_response: args.store_response,
        store_response_dir: args.store_response_dir,
        custom_fields_config: args.config,
        ..Default::default()
    };

    let engine: Arc<dyn Engine> = if options.headless_hybrid {
        Arc::new(HybridEngine::new(options)?)
    } else if options.headless {
        Arc::new(HeadlessEngine::new(options)?)
    } else {
        Arc::new(StandardEngine::new(options)?)
    };

    let writer = OutputWriter::new(args.jsonl, args.output.as_deref());
    let (tx, mut rx) = mpsc::unbounded_channel();

    // Spawn output processor
    let output_handle = tokio::spawn(async move {
        while let Some(res) = rx.recv().await {
            writer.write_result(&res);
        }
    });

    for target in target_urls {
        if let Err(e) = engine.crawl(&target, tx.clone()).await {
            eprintln!("Crawl error for {}: {}", target, e);
        }
    }

    drop(tx);
    let _ = output_handle.await;

    Ok(())
}
