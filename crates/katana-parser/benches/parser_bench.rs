use criterion::{black_box, criterion_group, criterion_main, Criterion};
use katana_parser::js::{extract_js_ast_endpoints, is_common_js_library};
use katana_parser::regex::extract_endpoints_from_regex;
use katana_parser::{parse_forms, parse_html_endpoints};

fn bench_html_parser(c: &mut Criterion) {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="/static/css/main.css">
            <script src="/static/js/bundle.js"></script>
        </head>
        <body>
            <a href="/home">Home</a>
            <a href="/dashboard/settings">Settings</a>
            <img src="/images/logo.png" />
            <form action="/login" method="POST">
                <input name="username" type="text" />
                <input name="password" type="password" />
            </form>
            <div data-src="/api/v1/details"></div>
        </body>
        </html>
    "#;

    c.bench_function("parse_html_endpoints", |b| {
        b.iter(|| parse_html_endpoints(black_box("https://example.com/"), black_box(html), 1))
    });

    c.bench_function("parse_forms", |b| b.iter(|| parse_forms(black_box(html))));
}

fn bench_regex_and_js_ast(c: &mut Criterion) {
    let js_code = r#"
        const API_URL = "https://api.example.com/v1/auth";
        fetch('/api/v2/user/profile', { method: 'GET' });
        axios.post('/api/v3/submit', { data: 123 });
        let route = `/api/v4/items/${id}/view`;
        const vendor = "/node_modules/react/index.js";
    "#;

    c.bench_function("extract_endpoints_from_regex", |b| {
        b.iter(|| {
            extract_endpoints_from_regex(
                black_box("https://example.com/app.js"),
                black_box(js_code),
                1,
            )
        })
    });

    c.bench_function("extract_js_ast_endpoints", |b| {
        b.iter(|| {
            extract_js_ast_endpoints(
                black_box("https://example.com/app.js"),
                black_box(js_code),
                1,
                "script",
            )
        })
    });

    c.bench_function("is_common_js_library", |b| {
        b.iter(|| is_common_js_library(black_box("https://cdn.example.com/jquery-3.6.0.min.js")))
    });
}

criterion_group!(benches, bench_html_parser, bench_regex_and_js_ast);
criterion_main!(benches);
