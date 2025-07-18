/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.util.regex.Pattern;

import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@AssignmentHints({
  "path-traversal-profile-fix.hint1",
  "path-traversal-profile-fix.hint2",
  "path-traversal-profile-fix.hint3"
})
public class ProfileUploadFix extends ProfileUploadBase {

  public ProfileUploadFix(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    super(webGoatHomeDirectory);
  }

  @PostMapping(
      value = "/PathTraversal/profile-upload-fix",
      consumes = ALL_VALUE,
      produces = APPLICATION_JSON_VALUE)
  @ResponseBody
  public AttackResult uploadFileHandler(
      @RequestParam("uploadedFileFix") MultipartFile file,
      @RequestParam(value = "fullNameFix", required = false) String fullName,
      @CurrentUsername String username) {

    if (fullName != null && !fullName.isEmpty()) {
        Pattern allowedCharsPattern = Pattern.compile("^[a-zA-Z0-9_.-]+$");

      if (!allowedCharsPattern.matcher(fullName).matches()) {
          return failed(this)
              .output("Filename contains invalid characters.")
              .build();
      }
      if (fullName.startsWith(".") || fullName.contains("..") || fullName.contains("/") || fullName.contains("\\")) {
          return failed(this)
              .output("Filename contains forbidden path components or separators.")
              .build();
      }
    }
    
    return super.execute(file, fullName, username);
  }

  @GetMapping("/PathTraversal/profile-picture-fix")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(@CurrentUsername String username) {
    return super.getProfilePicture(username);
  }
}
