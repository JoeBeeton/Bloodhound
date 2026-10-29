package org.freedonia.bloodhound.worker.modules.exposure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Covers only the pure parsing logic (GithubSecretLeakFetcher.parseSearchHits/decodeBase64Content) against real GitHub API response shapes - the HTTP calls themselves are verified live, same convention as HibpFetcher/ZapScanRunner. */
class GithubSecretLeakFetcherTest {

    /** Shape captured from GitHub's documented code-search response (docs.github.com/en/rest/search/search#search-code). */
    private static final String REALISTIC_SEARCH_RESPONSE =
            """
            {
              "total_count": 1,
              "incomplete_results": false,
              "items": [
                {
                  "name": "secrets.js",
                  "path": "config/secrets.js",
                  "sha": "abc123",
                  "url": "https://api.github.com/repositories/123456/contents/config/secrets.js?ref=main",
                  "git_url": "https://api.github.com/repositories/123456/git/blobs/abc123",
                  "html_url": "https://github.com/acme/webapp/blob/main/config/secrets.js",
                  "repository": {
                    "id": 123456,
                    "full_name": "acme/webapp"
                  },
                  "score": 1.0
                }
              ]
            }
            """;

    @Test
    void parsesAllFieldsFromARealisticSearchResponse() {
        List<GithubSecretLeakFetcher.SearchHit> hits = GithubSecretLeakFetcher.parseSearchHits(REALISTIC_SEARCH_RESPONSE);

        assertThat(hits).hasSize(1);
        GithubSecretLeakFetcher.SearchHit hit = hits.get(0);
        assertThat(hit.repoFullName()).isEqualTo("acme/webapp");
        assertThat(hit.path()).isEqualTo("config/secrets.js");
        assertThat(hit.htmlUrl()).isEqualTo("https://github.com/acme/webapp/blob/main/config/secrets.js");
        assertThat(hit.contentsUrl()).isEqualTo("https://api.github.com/repositories/123456/contents/config/secrets.js?ref=main");
    }

    @Test
    void capsAtMaxCandidates_evenWhenGithubReturnsMore() {
        StringBuilder items = new StringBuilder();
        for (int i = 0; i < 15; i++) {
            if (i > 0) {
                items.append(",");
            }
            items.append(
                    """
                    {"path": "file%d.js", "url": "https://api.github.com/x%d", "html_url": "https://github.com/x%d",
                     "repository": {"full_name": "acme/repo"}}
                    """
                            .formatted(i, i, i));
        }
        String json = "{\"items\": [" + items + "]}";

        List<GithubSecretLeakFetcher.SearchHit> hits = GithubSecretLeakFetcher.parseSearchHits(json);

        assertThat(hits).hasSize(10);
    }

    @Test
    void itemMissingContentsUrl_skipped_notFatal() {
        String json = "{\"items\": [{\"path\": \"a.js\", \"repository\": {\"full_name\": \"acme/repo\"}}]}";

        assertThat(GithubSecretLeakFetcher.parseSearchHits(json)).isEmpty();
    }

    @Test
    void emptyItemsArray_producesEmptyList() {
        assertThat(GithubSecretLeakFetcher.parseSearchHits("{\"items\": []}")).isEmpty();
    }

    @Test
    void malformedJson_producesEmptyListRatherThanThrowing() {
        assertThat(GithubSecretLeakFetcher.parseSearchHits("not json at all")).isEmpty();
    }

    /** Shape captured from GitHub's documented Contents API response (docs.github.com/en/rest/repos/contents). */
    @Test
    void decodesABase64ContentsResponse_includingGithubsOwnEmbeddedNewlines() {
        // "hello world" base64-encoded, with an embedded newline exactly like GitHub's own API
        // inserts for readability in real responses - MIME-mode decoding (not basic/strict mode)
        // must tolerate this.
        String json =
                """
                {
                  "name": "secrets.js",
                  "path": "config/secrets.js",
                  "sha": "abc123",
                  "size": 11,
                  "content": "aGVsbG8g\\nd29ybGQ=",
                  "encoding": "base64"
                }
                """;

        assertThat(GithubSecretLeakFetcher.decodeBase64Content(json)).isEqualTo("hello world");
    }

    @Test
    void nonBase64Encoding_returnsNullRatherThanGarbage() {
        String json = "{\"content\": \"plain text\", \"encoding\": \"utf-8\"}";

        assertThat(GithubSecretLeakFetcher.decodeBase64Content(json)).isNull();
    }

    @Test
    void malformedContentsResponse_returnsNullRatherThanThrowing() {
        assertThat(GithubSecretLeakFetcher.decodeBase64Content("not json at all")).isNull();
    }
}
