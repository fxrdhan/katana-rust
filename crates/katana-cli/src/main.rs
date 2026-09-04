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

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();
    let normalized = flags::normalize_cli_args(raw_args);
    let args = CliArgs::parse_from(normalized);

    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(log_level))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut target_urls = Vec::new();
    if let Some(u) = args.url {
        target_urls.push(u);
    } else if let Some(list_path) = &args.list {
        let file = File::open(list_path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line_str = line?.trim().to_string();
            if !line_str.is_empty() {
                target_urls.push(line_str);
            }
        }
    } else if let Some(raw_path) = &args.raw_request {
        let parsed_req = katana_core::parse_raw_request_file(raw_path, true)?;
        target_urls.push(parsed_req.url);
    } else if let Some(resume_path) = &args.resume {
        let cp = katana_core::CrawlCheckpoint::load(resume_path)?;
        target_urls.extend(cp.in_flight_urls);
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
        eprintln!("Error: No target URLs provided. Use -u <url>, -l <file>, -r <raw-request>, or pipe via stdin");
        std::process::exit(1);
    }

    let mut custom_headers = std::collections::HashMap::new();
    for h in &args.headers {
        if let Some((k, v)) = h.split_once(':') {
            custom_headers.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    let crawl_duration = args.crawl_duration.as_deref().and_then(|d| {
        let d = d.trim();
        if let Some(s) = d.strip_suffix('s') {
            s.parse::<u64>().ok()
        } else if let Some(m) = d.strip_suffix('m') {
            m.parse::<u64>().ok().map(|v| v * 60)
        } else if let Some(h) = d.strip_suffix('h') {
            h.parse::<u64>().ok().map(|v| v * 3600)
        } else if let Some(day) = d.strip_suffix('d') {
            day.parse::<u64>().ok().map(|v| v * 86400)
        } else {
            d.parse::<u64>().ok()
        }
    });

    let options = Options {
        urls: target_urls.clone(),
        max_depth: args.depth,
        crawl_duration,
        concurrency: args.concurrency,
        parallelism: args.parallelism,
        delay: args.delay,
        rate_limit: args.rate_limit,
        rate_limit_minute: args.rate_limit_minute,
        scope: args.crawl_scope,
        out_of_scope: args.crawl_out_scope,
        field_scope: args.field_scope,
        no_scope: args.no_scope,
        custom_headers,
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
        raw_request_file: args.raw_request.clone(),
        resume_file: args.resume.clone(),
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

    let par_semaphore = Arc::new(tokio::sync::Semaphore::new(args.parallelism.max(1)));
    let mut join_handles = Vec::new();

    for target in target_urls {
        let permit = par_semaphore.clone().acquire_owned().await?;
        let engine_clone = engine.clone();
        let tx_clone = tx.clone();
        join_handles.push(tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = engine_clone.crawl(&target, tx_clone).await {
                eprintln!("Crawl error for {}: {}", target, e);
            }
        }));
    }

    for handle in join_handles {
        let _ = handle.await;
    }

    drop(tx);
    let _ = output_handle.await;

    Ok(())
}
