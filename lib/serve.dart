import 'dart:io' as io;

import 'package:mtnlu/router.dart';
import 'package:path/path.dart' as p;

/// Previews the static site.
final class HttpPreviewServer {
  final io.HttpServer _server;

  HttpPreviewServer._(this._server);

  static (String, String) _mimeType(String path) {
    return switch (p.extension(path)) {
      '.css' => ('text', 'css'),
      '.js' => ('application', 'javascript'),
      '.png' => ('image', 'png'),
      '.jpg' || '.jpeg' => ('image', 'jpeg'),
      '.svg' => ('image', 'svg+xml'),
      '.woff2' => ('font', 'woff2'),
      '.txt' => ('text', 'plain'),
      '.html' || '' => ('text', 'html'),
      _ => ('application', 'octet-stream'),
    };
  }

  /// Starts a server to preview the static site.
  static Future<HttpPreviewServer> start({
    required String templatePath,
    required String staticPath,
    required String contentPath,
  }) async {
    final server = await io.HttpServer.bind(
      io.InternetAddress.loopbackIPv4,
      0,
    );

    final router = SiteRouter(
      contentPath: contentPath,
      staticPath: staticPath,
      templatePath: templatePath,
      baseUri: Uri(
        scheme: 'http',
        host: server.address.host,
        port: server.port,
      ),
    );

    server.listen((request) async {
      final path = request.uri.path;
      final content = await router.handle(path);
      if (content == null) {
        request.response.statusCode = io.HttpStatus.notFound;
      } else {
        final mimeType = _mimeType(path);
        request.response.headers.contentType = io.ContentType(
          mimeType.$1,
          mimeType.$2,
        );
        request.response.add(content);
      }
      await request.response.flush();
      await request.response.close();
    });

    return HttpPreviewServer._(server);
  }

  /// Closes the server.
  Future<void> close() => _server.close();

  /// The port the server is running on.
  int get port => _server.port;
}
