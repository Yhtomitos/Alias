# API Documentation Standard

This project treats public API documentation as part of the API contract. When agents or contributors add, change, or remove public behavior, they must update the relevant code comments and Markdown documentation in the same change.

## Agent Documentation Workflow

1. Identify every public API, configuration shape, serialized schema, command, and user-facing workflow touched by the change.
2. Update language-native API documentation next to the code.
3. Update Markdown documentation under `docs/` when behavior, architecture, security assumptions, crypto formats, agent permissions, or contribution workflows change.
4. Keep documentation focused on behavior, contracts, errors, safety assumptions, examples, and side effects.
5. Do not document obvious implementation details that are already clear from names and types.
6. Verify documentation with the same care as code by running relevant tests, linters, formatters, or documentation checks when available.

## Rust

Use rustdoc documentation comments.

- Use `//!` for crate-level and module-level documentation.
- Use `///` for public structs, enums, traits, functions, constants, and public fields when the field's meaning is not obvious.
- Document behavior and contracts rather than implementation details.
- Document errors for functions returning `Result`.
- Document safety assumptions and invariants, especially for cryptography and secret handling.
- Include examples for public APIs when they clarify expected use.
- Never include real secrets in examples, tests, or rendered documentation.

Primary references:

- <https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html>
- <https://rust-lang.github.io/rfcs/0505-api-comment-conventions.html>

## TypeScript

Use JSDoc/TSDoc-style block comments for exported APIs.

- Use `/** ... */` for exported functions, classes, interfaces, types, hooks, components, and public configuration objects.
- Use `//` only for implementation reasoning or non-obvious local decisions.
- Do not repeat information already obvious from TypeScript types.
- Document side effects, security boundaries, async behavior, and thrown errors.

Primary references:

- <https://www.typescriptlang.org/docs/handbook/jsdoc-supported-types.html>
- <https://google.github.io/styleguide/tsguide.html>

## Python

Use PEP 257 docstrings and PEP 8 comments.

- Use triple-double-quoted docstrings for public modules, classes, functions, and methods.
- Describe arguments, return values, raised exceptions, and side effects when they are not obvious.
- Use complete-sentence comments.
- Comments should explain why code exists or why an approach is required, not restate what the code does.

Primary references:

- <https://peps.python.org/pep-0257/>
- <https://peps.python.org/pep-0008/>

## HTML

Use HTML comments sparingly.

- Use comments only for structural landmarks or non-obvious decisions.
- Do not add comments that duplicate visible content or semantic markup.
- Do not place secrets, internal URLs, or sensitive deployment details in comments.

Primary reference:

- <https://developer.mozilla.org/en-US/docs/Web/HTML/Guides/Comments>

## CSS

Use CSS comments sparingly.

- Use `/* ... */` comments.
- Document unusual layout, security, accessibility, browser-compatibility, or rendering decisions.
- Do not comment routine declarations.

Primary reference:

- <https://developer.mozilla.org/en-US/docs/Web/CSS/Guides/Syntax/Comments>

## Markdown

Use CommonMark-compatible Markdown for project documentation.

- Keep architecture, security, contribution, threat-model, crypto-format, vault-format, and agent-security documentation in Markdown.
- Prefer clear headings, short paragraphs, and fenced code blocks with language identifiers.
- Update documents when code changes alter documented behavior, supported formats, security assumptions, or developer workflows.
- Avoid stale roadmap claims; mark speculative or future behavior clearly.

Primary reference:

- <https://spec.commonmark.org/>

## Documentation Review Checklist

- Public Rust APIs have rustdoc comments.
- Exported TypeScript APIs have JSDoc/TSDoc comments.
- Public Python APIs have PEP 257 docstrings.
- Markdown docs are updated for behavior, architecture, security, and workflow changes.
- Comments explain contracts, risks, and reasoning rather than obvious code.
- Examples use fake data and never include real secrets.
- Errors, side effects, and safety assumptions are documented.
