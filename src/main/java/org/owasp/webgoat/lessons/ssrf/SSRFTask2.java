/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.Arrays;
import java.util.List;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

  private static final List<String> ALLOWED_EXTERNAL_DOMAINS = Arrays.asList("ifconfig.pro");

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

protected boolean isInternalHost(java.net.URL parsedUrl) throws java.io.IOException {
    String inputHost = parsedUrl.getHost();
    java.net.InetAddress[] addresses = java.net.InetAddress.getAllByName(inputHost);
    for (java.net.InetAddress addr : addresses) {
        if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()) {
            return true;
        }
    }
    return false;
}

protected AttackResult furBall(String url) {
    String html;
    try {
        java.net.URL parsedUrl = new java.net.URI(url).toURL();

        // 1. Domain Whitelist Check
        if (!ALLOWED_EXTERNAL_DOMAINS.contains(parsedUrl.getHost())) {
            return failed(this)
                .feedback("SSRF: Access to unauthorized external domain is blocked!")
                .output("Attempted to access: " + url + ". Only " + ALLOWED_EXTERNAL_DOMAINS + " are allowed.")
                .build();
        }

        // 2. Internal/Loopback IP Check (handles DNS rebinding for internal addresses)
        if (isInternalHost(parsedUrl)) {
            return failed(this)
                .feedback("SSRF: Access to internal or loopback IPs is blocked!")
                .output("Attempted to access: " + url + " which resolved to an internal/loopback address")
                .build();
        }

        try (java.io.InputStream in = parsedUrl.openStream()) {
            html = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).replaceAll("\n", "<br>");
        } catch (java.io.IOException e) {
            return failed(this)
                .output("The remote site is unreachable or down: " + e.getMessage())
                .build();
        }

        return failed(this).feedback("ssrf.failed").output(html).build();
    } catch (java.net.MalformedURLException | java.net.URISyntaxException e) {
        return getFailedResult("Error processing URL: " + e.getMessage());
    } catch (java.io.IOException e) {
        return getFailedResult("Network or connection error during host resolution: " + e.getMessage());
    }
}

private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
