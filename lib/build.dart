import 'dart:io' as io;

import 'package:mtnlu/template.dart';
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

  // Generate HTML files for each content file.
  // For example content/index.html -> output/index.html.
  final template = await io.File(templatePath).readAsString();
  final contentDir = io.Directory(contentPath);
  await for (final entity in contentDir.list(recursive: true)) {
    if (entity is io.File) {
      final content = await entity.readAsString();
      final newPath = p.join(
        outputPath,
        p.setExtension(
          p.relative(entity.path, from: contentPath),
          '.html',
        ),
      );
      final newDir = io.Directory(p.dirname(newPath));
      await newDir.create(recursive: true);
      await io.File(newPath).writeAsString(
        renderContent(template, content: content, server: server),
      );
    }
  }
}
