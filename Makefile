clean:
	@echo "Clearing the previous build..."
	@rm -rf build

build: build.copy
	@echo "Building static website..."

build.copy: clean
	@echo "Copying static files..."
	@mkdir build
	@cp index.html build/index.html
	@cp site.css build/site.css
	@cp -R images build/images
