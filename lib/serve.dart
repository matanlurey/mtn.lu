import 'dart:io' as io;

import 'package:mtnlu/template.dart';
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
    required String contentPath,
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
          '' => ('text', 'plain'),
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
        final file = io.File(
          p.join(
            contentPath,
            '${path == '/' ? 'index' : path.substring(1)}.html',
          ),
        );
        if (!await file.exists()) {
          io.stderr.writeln('404 Not Found: ${file.path} ($path)');
          request.response.statusCode = io.HttpStatus.notFound;
          await request.response.close();
          return;
        }

        final content = await file.readAsString();
        final template = await io.File(templatePath).readAsString();
        request.response.headers.contentType = io.ContentType.html;
        final serverUrl = Uri(
          scheme: 'http',
          host: 'localhost',
          port: server.port,
        );
        request.response.write(
          renderContent(
            template,
            server: serverUrl,
            content: content,
          ),
        );
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
