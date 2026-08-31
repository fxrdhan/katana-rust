mod flags;
mod output;

use clap::Parser;
use flags::CliArgs;
use katana_core::options::Options;
use katana_engine::{Engine, StandardEngine};
use output::OutputWriter;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
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
        scrape_js: args.js_crawl,
        form_extraction: args.form_extraction,
        ignore_query_params: args.ignore_query_params,
        filter_similar: args.filter_similar,
        path_climb: args.path_climb,
        max_domain_pages: args.max_domain_pages,
        display_out_scope: args.display_out_scope,
        proxy: args.proxy,
        ..Default::default()
    };

    let engine = StandardEngine::new(options)?;
    let writer = OutputWriter::new(args.jsonl);

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
