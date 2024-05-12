import 'dart:io' as io;

import 'package:mtnlu/router.dart';
import 'package:path/path.dart' as p;

/// Builds a static website into [outputPath].
Future<void> build({
  required String templatePath,
  required String outputPath,
  required String staticPath,
  required String contentPath,
  required Uri server,
}) async {
  // Delete the output directory if it exists.
  final outputDir = io.Directory(outputPath);
  if (await outputDir.exists()) {
    await outputDir.delete(recursive: true);
  }

  // Create the output directory.
  await outputDir.create(recursive: true);

  // Copy files from static directory.
  final staticDir = io.Directory(staticPath);
  await for (final entity in staticDir.list(recursive: true)) {
    if (entity is io.File) {
      final newPath = p.join(
        outputPath,
        p.relative(entity.path, from: staticPath),
      );
      final newDir = io.Directory(p.dirname(newPath));
      await newDir.create(recursive: true);
      await io.File(entity.path).copy(newPath);
    }
  }

  // Crawl the content directory and render HTML files.
  final router = SiteRouter(
    contentPath: contentPath,
    staticPath: outputPath,
    templatePath: templatePath,
    baseUri: server,
  );

  final contentDir = io.Directory(contentPath);
  await for (final entity in contentDir.list(recursive: true)) {
    if (entity is io.File && entity.path.endsWith('.html')) {
      // Generate the 'URL' for the content file.
      // For example, /content/about.html -> /about
      var path = p.withoutExtension(
        p.relative(entity.path, from: contentPath),
      );

      // If the path is /content/posts/{year}-{month}-{day}-{slug}
      // Then the URL should be /posts/{year}/{month}/{day}/{slug}
      final blogMatch = RegExp(
        r'^posts\/(\d{4})-(\d{2})-(\d{2})-(.*)$',
      ).firstMatch(path);
      if (blogMatch != null) {
        final [year, month, day, slug] = blogMatch.groups([1, 2, 3, 4]);
        path = '$year/$month/$day/$slug';
      }

      // Render the content file.
      final content = await router.handle(path);
      if (content == null) {
        throw Exception('Failed to render $path');
      }

      // And if it was a blog, output/{year}/{month}/{day}/{slug}.html
      if (blogMatch != null) {
        path = p.join(
          blogMatch.group(1)!,
          blogMatch.group(2)!,
          blogMatch.group(3)!,
          blogMatch.group(4)!,
        );
      }

      // Write the rendered content to the output directory.
      final newPath = p.join(outputPath, '$path.html');
      final newDir = io.Directory(p.dirname(newPath));
      await newDir.create(recursive: true);
      await io.File(newPath).writeAsBytes(content);
    }
  }
}
