import 'dart:convert';
import 'dart:io' as io;

import 'package:mtnlu/template.dart';
import 'package:path/path.dart' as p;

/// A router for serving static and content files.
final class SiteRouter {
  /// Creates a new router.
  ///
  /// - [contentPath]: The path to the `content` directory.
  /// - [staticPath]: The path to the `static` directory.
  /// - [templatePath]: The path to the `template.html` file.
  /// - [baseUri]: The base URI for the server.
  SiteRouter({
    required String contentPath,
    required String staticPath,
    required String templatePath,
    required Uri baseUri,
  })  : _contentPath = contentPath,
        _staticPath = staticPath,
        _templatePath = templatePath,
        _baseUri = baseUri;

  final String _contentPath;
  final String _staticPath;
  final String _templatePath;
  final Uri _baseUri;

  /// Handles a request, returning the content.
  ///
  /// If the request is for a static file, it will be served from the `static`
  /// directory. If the request is for a content file, it will be served from
  /// the `content` directory.
  ///
  /// If the file does not exist, `null` will be returned.
  Future<List<int>?> handle(String path) async {
    if (path.startsWith(p.separator)) {
      path = path.substring(1);
    }

    // Check if the file exists in the static directory.
    final staticFile = io.File(p.join(_staticPath, path));
    if (await staticFile.exists()) {
      return staticFile.readAsBytes();
    }

    // Check if the file exists in the content directory.
    // Unlike static, we need to add the `.html` extension and apply a template.
    // If the URL is blank, serve the index file.
    if (path.isEmpty) {
      path = 'index';
    }

    // If we match the path: '{year}/{month}/{day}/{slug}'
    // Then the content file is actually located at:
    // content/{year}-{month}-{day}-{slug}.html
    final blogMatch = RegExp(
      r'^(\d{4})/(\d{2})/(\d{2})/(.*)$',
    ).firstMatch(path);
    if (blogMatch != null) {
      final [year, month, day, slug] = blogMatch.groups([1, 2, 3, 4]);
      path = p.join(
        'posts',
        '$year-$month-$day-$slug',
      );
    }

    final contentFile = io.File(p.join(_contentPath, '$path.html'));
    if (await contentFile.exists()) {
      var content = await contentFile.readAsString();
      // If it was the index, we need more template logic.
      if (path == 'index') {
        // Find all of the blog posts in the content directory.
        final posts = [
          for (final entity in await io.Directory(p.join(_contentPath, 'posts'))
              .list()
              .toList())
            if (entity is io.File && entity.path.endsWith('.html')) entity.path,
        ];

        content = renderContent(
          content,
          content:
              '<ul>${(await Future.wait(posts.map(_renderPost))).join()}</ul>',
          server: _baseUri,
        );
      }

      final template = await io.File(_templatePath).readAsString();
      final rendered = renderContent(
        template,
        content: content,
        server: _baseUri.resolve(path == 'index' ? '' : path),
      );

      // Return as UTF-8 bytes.
      return utf8.encode(rendered);
    }

    // If the file does not exist, return null.
    return null;
  }
}

Future<String> _renderPost(String path) async {
  // Load the HTML content of the post.
  final content = await io.File(path).readAsString();

  // Rename the path to be the URL.
  // i.e. posts/2024-05-12-hello-world.html -> 2024/05/12/hello-world
  var url = p.withoutExtension(
    p.relative(
      path,
      from: p.join('content', 'posts'),
    ),
  );

  // Replace - with / for the date in the URL (i.e. the first 3).
  for (var i = 0; i < 3; i++) {
    final index = url.indexOf('-');
    url = url.replaceRange(index, index + 1, '/');
  }

  // Parse the title and date from the content.
  //
  // <h1>Hello World</h1>
  // <time datetime="2024-05-12">May 12, 2024</time>
  final title = RegExp('<h1>(.*)</h1>').firstMatch(content)?.group(1);
  final [date, dateName] = RegExp('<time datetime="(.*)">(.*)</time>')
      .firstMatch(content)!
      .groups([1, 2]);

  // Generate the post.
  return '''
    <li>
      <h2>
        <time datetime="$date">$dateName</time>
        <a href="$url">
          $title
        </a>
      </h2>
    </li>
  ''';
}
