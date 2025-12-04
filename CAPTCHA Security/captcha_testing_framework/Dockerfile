# Builder stage
FROM rust:bullseye as builder

# Set the working directory
WORKDIR /usr/src/captcha_testing_framework

# Copy your Cargo.toml into the image
COPY ./Cargo.toml ./Cargo.toml

# Create a dummy main.rs file to compile dependencies
RUN mkdir src \
    && echo "fn main() {println!(\"if you see this, the build broke\");}" > src/main.rs

# Build the application to cache the dependencies
RUN cargo build --release

# Remove the dummy source and target directory, then copy the actual source code
RUN rm -rf ./src ./target/release/deps/captcha_testing_framework*
COPY ./src ./src
COPY ./static ./static

# Rebuild the application with the actual source code
RUN cargo build --release

# Runtime stage
FROM debian:bullseye-slim

# Install CA certificates
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    update-ca-certificates && \
    # Clean up APT cache to reduce image size
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the application
RUN useradd -m dummy

# Switch to the non-root user
USER dummy

# Copy the binary from the builder stage
COPY --from=builder /usr/src/captcha_testing_framework/target/release/captcha_testing_framework /usr/local/bin/captcha_testing_framework
COPY --from=builder /usr/src/captcha_testing_framework/static/ /usr/src/captcha_testing_framework/static/

# Expose port 8080
EXPOSE 8080

# Set static path
ENV STATIC_PATH=/usr/src/captcha_testing_framework/static/

# Command to run the application
CMD ["/usr/local/bin/captcha_testing_framework"]
