import 'dart:io' as io;

import 'package:path/path.dart' as p;

/// Previews the static site.
final class HttpPreviewServer {
  final io.HttpServer _server;

  HttpPreviewServer._(this._server);

  /// Starts a server to preview the static site.
  static Future<HttpPreviewServer> start({
    required String templatePath,
    required String outputPath,
    required String staticPath,
  }) async {
    final server = await io.HttpServer.bind(
      io.InternetAddress.loopbackIPv4,
      0,
    );

    server.listen((request) async {
      // If it's a relative file that is in staticPath, serve it.
      final path = request.uri.path;
      final file = io.File(p.join(staticPath, path.substring(1)));

      if (await file.exists()) {
        // Add the a mime type based on the file extension.
        final (primary, secondary) = switch (p.extension(file.path)) {
          '.css' => ('text', 'css'),
          '.html' => ('text', 'html'),
          '.js' => ('application', 'javascript'),
          '.svg' => ('image', 'svg+xml'),
          '.woff2' => ('font', 'woff2'),
          _ => ('application', 'octet-stream'),
        };

        request.response.headers.contentType = io.ContentType(
          primary,
          secondary,
        );
        await request.response.addStream(file.openRead());
        await request.response.close();
        return;
      } else {
        // Otherwise, serve the generated index.html file.
        final template = await io.File(templatePath).readAsString();
        request.response.headers.contentType = io.ContentType.html;
        request.response.write(template);
        await request.response.flush();
        await request.response.close();
      }
    });

    return HttpPreviewServer._(server);
  }

  /// Closes the server.
  Future<void> close() => _server.close();

  /// The port the server is running on.
  int get port => _server.port;
}
