from __future__ import annotations
import re
from urllib.parse import urlparse, urlunparse, urlencode
from .base import BaseModule
from ..scanner import Finding, HIGH, mutate_query

class XSSModule(BaseModule):
    name = "Cross-Site Scripting"
    category = "Injection"

    def run(self):
        # _confirmed tracks (base_url, param) pairs already reported so we emit
        # one finding per vulnerable parameter, not one per payload variant.
        self._confirmed: set[tuple[str, str]] = set()

        payloads = [
            # Reflected XSS — break-out probes
            'xploit"><svg/onload=alert(1)>',
            'xploit"><img src=x onerror=alert(1)>',
            'xploit\'><script>alert(1)</script>',
            'xploit"><details open ontoggle=alert(1)>',
            'xploit"><iframe src="javascript:alert(1)">',
            'xploit" onmouseover="alert(1)',
            'xploit"><a href="javascript:alert(1)">click</a>',
            'xploit"><video><source onerror=alert(1)>',
            'xploit"><body onload=alert(1)>',
            'xploit"><marquee onstart=alert(1)>',
            # DOM / href-sink probes
            '<img src=x onerror=alert(document.domain)>',
            'javascript:alert(document.cookie)',
            '<svg onload=alert(1)>',
            # Filter bypass variants
            '<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
            '<IMG SRC=x OnErRoR=alert(1)>',
            '<img src=x onerror=alert(1)>',
            # Advanced context probes
            'xploit"><math><mtext><option><annotation encoding="text/html"><svg/onload=alert(1)></annotation></option></mtext></math>',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
        ]
        for payload in payloads:
            for url in list(self.scanner.pages):
                self._check_url(url, payload)
            for form in self.scanner.forms:
                self._check_form(form, payload)

    @staticmethod
    def _base_url(url: str) -> str:
        """Strip query string and fragment — used as the canonical finding URL."""
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))

    def _check_url(self, url, payload):
        from ..scanner import query_parameters
        for param in query_parameters(url):
            base = self._base_url(url)
            if (base, param) in self._confirmed:
                continue
            target_url = mutate_query(url, param, payload)
            res = self.scanner._request("GET", target_url)
            if res:
                self._analyze_reflection(res, base, param, payload, "GET",
                                         proof_url=target_url)

    def _check_form(self, form, payload):
        base = self._base_url(form.action)
        for param in form.inputs:
            if (base, param) in self._confirmed:
                continue
            data = dict(form.inputs)
            data[param] = payload
            if form.method == "GET":
                sep = "&" if urlparse(form.action).query else "?"
                proof_url = form.action + sep + urlencode(data)
                res = self.scanner._request("GET", form.action, params=data)
                proof_data = ""
            else:
                proof_url = form.action
                res = self.scanner._request("POST", form.action, data=data)
                proof_data = urlencode(data)
            if res:
                self._analyze_reflection(res, base, param, payload, form.method,
                                         proof_url=proof_url, proof_data=proof_data)

    @staticmethod
    def _executable_context(before: str, payload: str = "") -> tuple[bool, str]:
        """Decide whether the HTML preceding a reflection point can execute.

        Only the markup BEFORE the payload is examined — the payload's own
        tags must never count as evidence of executability (that was the old
        vacuous check: 19 of 20 payloads contain the markers being searched
        for, so any verbatim reflection "confirmed"). The payload itself is
        consulted only for the javascript:-URI-in-URL-attribute case, where
        the scheme comes from the payload, not the surrounding markup.
        """
        lower = before.lower()
        # Inside an HTML comment: inert.
        if lower.rfind("<!--") > lower.rfind("-->"):
            return False, "inside HTML comment"
        # Inside raw-text elements: reflected markup is inert text.
        for tag in ("textarea", "title", "style", "noscript"):
            if lower.rfind(f"<{tag}") > lower.rfind(f"</{tag}>"):
                return False, f"inside <{tag}>"
        # Inside a <script> block the payload is JS source, not HTML — whether
        # it breaks out of a string/comment can't be confirmed statically.
        if lower.rfind("<script") > lower.rfind("</script>"):
            return False, "inside <script> block (unconfirmed JS context)"
        # Inside a tag (attribute value) vs. in element body?
        last_lt, last_gt = lower.rfind("<"), lower.rfind(">")
        if last_lt > last_gt:
            tag_text = lower[last_lt:]
            if re.search(r"\son\w+\s*=", tag_text) or "javascript:" in tag_text:
                return True, "inside event-handler / javascript: attribute"
            # A javascript: URI payload reflected into a URL-bearing attribute
            # is executable even though the preceding markup alone looks inert
            # (e.g. <a href=" + javascript:alert(1)). Other attributes holding
            # the same text are not.
            if payload.lower().lstrip().startswith("javascript:"):
                attr = re.search(r"([\w:-]+)\s*=\s*[\"']?$", tag_text)
                if attr and attr.group(1) in (
                    "href", "src", "action", "formaction", "xlink:href",
                    "data", "poster", "cite", "longdesc", "profile", "usemap",
                    "background",
                ):
                    return True, "javascript: URI in URL attribute"
            return False, "inside inert attribute value"
        return True, "HTML element body"

    def _analyze_reflection(self, response, base_url, parameter, payload, method,
                            proof_url, proof_data=""):
        # Missing Content-Type is scannable (browsers sniff it); only skip when
        # the server explicitly declares a non-HTML type.
        content_type = response.headers.get("Content-Type", "")
        if content_type and "text/html" not in content_type.lower():
            return
        if payload not in response.text:
            return

        idx = response.text.find(payload)
        before = response.text[max(0, idx - 500):idx]
        executable, context_desc = self._executable_context(before, payload)
        if not executable:
            return
        # The payload itself must carry an active vector — reflection of a
        # benign string into an executable context is not XSS.
        if not any(p in payload.lower() for p in ["<svg", "<img", "<script", "onerror",
                                                  "onload", "ontoggle", "onmouseover",
                                                  "onstart", "javascript:"]):
            return

        self._confirmed.add((base_url, parameter))
        finding = Finding(
            id="XSS-001",
            name="Reflected XSS",
            category="Cross-Site Scripting",
            severity=HIGH,
            confidence="High",
            url=base_url,
            parameter=parameter,
            method=method,
            evidence=f"Payload reflected unescaped into {context_desc}: {payload[:60]} "
                     f"(static context analysis only — script execution was not "
                     f"dynamically confirmed in a browser)",
            trigger=f"payload={payload}",
            impact="Reflected HTML injection was observed in a statically executable DOM context. If a browser executes the injected context, attackers could run script in a victim's session.",
            remediation="Apply context-aware output encoding.",
            cwe="CWE-79"
        )
        # The reflected payload itself is the response marker: re-firing the
        # proof request and finding the payload again confirms the finding.
        self.attach_proof(finding, method=method, url=proof_url,
                          marker=payload, data=proof_data)
        self.add_finding(finding)
