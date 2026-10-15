//! Docmost embed providers: which URLs Docmost turns into an `embed` node.

use std::sync::LazyLock;

use regex::Regex;

/// `(provider, URL pattern)` pairs, ported from Docmost's `embed-provider.ts`
/// (`packages/editor-ext`, 0.96). The provider string is the provider's display name
/// lowercased, which is what Docmost stores in the node's `provider` attr. Docmost's
/// catch-all `iframe` provider is left out: its import never embeds an unknown URL.
static PROVIDERS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        (
            "loom",
            r"^https?://(?:www\.)?loom\.com/(?:share|embed)/([\da-zA-Z]+)/?",
        ),
        ("airtable", r"^https://(www.)?airtable.com/([a-zA-Z0-9]{2,})/.*"),
        (
            "figma",
            r"^https://[\w\.-]+\.?figma.com/(file|proto|board|design|slides|deck)/([0-9a-zA-Z]{22,128})",
        ),
        ("typeform", r"^(https?:)?(//)?[\w\.]+\.typeform\.com/to/.+"),
        ("miro", r"^https://(www\.)?miro\.com/app/board/([\w-]+=)"),
        (
            "youtube",
            r"^((?:https?:)?//)?((?:www|m|music)\.)?((?:youtube\.com|youtu.be))(/(?:[\w\-]+\?v=|embed/|v/)?)([\w\-]+)(\S+)?$",
        ),
        (
            "vimeo",
            r"^(https:)?//(?:www\.|player\.)?vimeo.com/(?:channels/(?:\w+/)?|groups/([^/]*)/videos/|album/(\d+)/video/|video/|)(\d+)(?:/([\da-zA-Z]+))?",
        ),
        ("framer", r"^https://(www\.)?framer\.com/embed/([\w-]+)"),
        (
            "google drive",
            r"^((?:https?:)?//)?((?:www|m)\.)?(drive\.google\.com)/file/d/([a-zA-Z0-9_-]+)/.*$",
        ),
        (
            "google sheets",
            r"^((?:https?:)?//)?((?:www|m)\.)?(docs\.google\.com)/spreadsheets/d/([a-zA-Z0-9_-]+)/.*$",
        ),
    ]
    .into_iter()
    .map(|(provider, pattern)| {
        (
            provider,
            Regex::new(pattern).expect("embed provider pattern is valid"),
        )
    })
    .collect()
});

/// The Docmost embed provider for `url`, or `None` when Docmost would leave it a link.
pub(super) fn embed_provider(url: &str) -> Option<&'static str> {
    PROVIDERS
        .iter()
        .find(|(_, pattern)| pattern.is_match(url))
        .map(|(provider, _)| *provider)
}

#[cfg(test)]
mod tests {
    use super::embed_provider;

    #[test]
    fn recognizes_docmost_providers() {
        for (url, provider) in [
            ("https://www.youtube.com/watch?v=Op-LKk-i4zQ", "youtube"),
            ("https://youtu.be/Op-LKk-i4zQ", "youtube"),
            ("https://vimeo.com/76979871", "vimeo"),
            ("https://www.loom.com/share/0123abcd", "loom"),
            (
                "https://drive.google.com/file/d/1AbC_d-E/view",
                "google drive",
            ),
            (
                "https://docs.google.com/spreadsheets/d/1AbC_d-E/edit",
                "google sheets",
            ),
        ] {
            assert_eq!(embed_provider(url), Some(provider), "{url}");
        }
    }

    #[test]
    fn other_urls_are_not_embeds() {
        for url in [
            "https://example.com/watch?v=x",
            "https://docs.google.com/document/d/1AbC/edit",
            "not a url",
        ] {
            assert_eq!(embed_provider(url), None, "{url}");
        }
    }
}
