"""Kalypso CLI — manage your local dev CA from the terminal."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from kalypso.ca import CertificateAuthority

DEFAULT_DATA_DIR = Path.home() / ".kalypso"


@click.group()
@click.option(
    "--data-dir",
    type=click.Path(path_type=Path),
    default=DEFAULT_DATA_DIR,
    envvar="KALYPSO_DATA_DIR",
    help="Directory to store CA data",
)
@click.pass_context
def main(ctx: click.Context, data_dir: Path) -> None:
    """Kalypso — Local dev SSL certificate authority."""
    ctx.ensure_object(dict)
    ctx.obj["data_dir"] = data_dir


@main.command()
@click.option("--org", default="Kalypso Dev CA", help="Organization name for the CA")
@click.pass_context
def init(ctx: click.Context, org: str) -> None:
    """Initialize a new root CA."""
    data_dir: Path = ctx.obj["data_dir"]
    cert_path = data_dir / "ca-cert.pem"
    key_path = data_dir / "ca-key.pem"

    if cert_path.exists():
        click.echo(f"CA already exists at {data_dir}", err=True)
        click.echo("Use --data-dir to specify a different location, or remove the existing CA.")
        sys.exit(1)

    data_dir.mkdir(parents=True, exist_ok=True)
    ca = CertificateAuthority.init(organization=org)
    ca.root.save(cert_path, key_path)

    click.echo(f"Root CA created at {data_dir}")
    click.echo(f"  Certificate:  {cert_path}")
    click.echo(f"  Private key:  {key_path} (mode 0600)")
    click.echo(f"  Fingerprint:  {ca.root.cert_fingerprint}")
    click.echo()
    click.echo("Next: trust the CA in your system/browser:")
    click.echo("  kalypso trust")
    click.echo()
    click.echo("Or manually:")
    _print_trust_instructions(cert_path)


def _print_trust_instructions(cert_path: Path) -> None:
    from kalypso.trust import trust_instructions

    for line in trust_instructions(cert_path):
        click.echo(f"  {line}")


@main.command()
@click.argument("domains", nargs=-1, required=True)
@click.option("--hours", default=24, help="Certificate lifetime in hours (max 168)")
@click.option("--ip", multiple=True, help="IP addresses to include in the SAN")
@click.option("--out", type=click.Path(path_type=Path), default=Path("."), help="Output directory")
@click.pass_context
def issue(ctx: click.Context, domains: tuple[str, ...], hours: int, ip: tuple[str, ...], out: Path) -> None:
    """Issue a short-lived certificate for DOMAINS."""
    data_dir: Path = ctx.obj["data_dir"]
    cert_path = data_dir / "ca-cert.pem"
    key_path = data_dir / "ca-key.pem"

    if not cert_path.exists():
        click.echo("No CA found. Run `kalypso init` first.", err=True)
        sys.exit(1)

    ca = CertificateAuthority.load(cert_path, key_path)
    bundle = ca.issue(*domains, hours=hours, ip_addresses=list(ip) if ip else None)

    out.mkdir(parents=True, exist_ok=True)
    bundle.save(out / "cert.pem", out / "key.pem")

    click.echo(f"Certificate issued for: {', '.join(domains)}")
    click.echo(f"  Valid for: {hours} hours")
    click.echo(f"  Certificate: {out / 'cert.pem'}")
    click.echo(f"  Private key: {out / 'key.pem'}")
    click.echo(f"  Fingerprint: {bundle.cert_fingerprint}")


@main.command()
@click.pass_context
def serve(ctx: click.Context) -> None:
    """Start the Kalypso API server."""
    import uvicorn

    data_dir: Path = ctx.obj["data_dir"]
    cert_path = data_dir / "ca-cert.pem"
    key_path = data_dir / "ca-key.pem"

    if cert_path.exists():
        from kalypso.server import CA_CERT_PATH as _  # noqa: F401
        import kalypso.server as srv

        srv.CA_CERT_PATH = cert_path
        srv.CA_KEY_PATH = key_path

    click.echo("Starting Kalypso server on http://0.0.0.0:8200")
    uvicorn.run("kalypso.server:app", host="0.0.0.0", port=8200, log_level="info")


@main.command()
@click.pass_context
def trust(ctx: click.Context) -> None:
    """Install the CA certificate into system trust stores.

    Automatically detects your OS and installs into the right places:
    macOS System Keychain, Linux system trust store, Firefox NSS,
    or Windows Certificate Store. No extra tools needed.
    """
    data_dir: Path = ctx.obj["data_dir"]
    cert_path = data_dir / "ca-cert.pem"

    if not cert_path.exists():
        click.echo("No CA found. Run `kalypso init` first.", err=True)
        sys.exit(1)

    from kalypso.trust import install

    click.echo("Installing CA into system trust stores...")
    result = install(cert_path)

    if result.success:
        for store in result.stores_modified:
            click.echo(f"  Installed: {store}")
        click.echo("Done. Your browser and tools now trust Kalypso certificates.")
    else:
        click.echo("Could not auto-install (may need sudo).", err=True)
        for err in result.errors:
            click.echo(f"  Error: {err}", err=True)
        click.echo()
        click.echo("Install manually:")
        _print_trust_instructions(cert_path)
        sys.exit(1)


@main.command()
@click.pass_context
def untrust(ctx: click.Context) -> None:
    """Remove the CA certificate from system trust stores."""
    data_dir: Path = ctx.obj["data_dir"]
    cert_path = data_dir / "ca-cert.pem"

    if not cert_path.exists():
        click.echo("No CA found.", err=True)
        sys.exit(1)

    from kalypso.trust import uninstall

    click.echo("Removing CA from system trust stores...")
    result = uninstall(cert_path)

    if result.success:
        for store in result.stores_modified:
            click.echo(f"  Removed: {store}")
        click.echo("Done.")
    else:
        click.echo("Could not auto-remove.", err=True)
        for err in result.errors:
            click.echo(f"  Error: {err}", err=True)
        sys.exit(1)


@main.command(name="ca-cert")
@click.pass_context
def ca_cert(ctx: click.Context) -> None:
    """Print the CA certificate PEM to stdout."""
    data_dir: Path = ctx.obj["data_dir"]
    cert_path = data_dir / "ca-cert.pem"

    if not cert_path.exists():
        click.echo("No CA found. Run `kalypso init` first.", err=True)
        sys.exit(1)

    sys.stdout.buffer.write(cert_path.read_bytes())


@main.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show CA status, fingerprint, and key security info."""
    data_dir: Path = ctx.obj["data_dir"]
    cert_path = data_dir / "ca-cert.pem"
    key_path = data_dir / "ca-key.pem"

    if not cert_path.exists():
        click.echo("No CA found. Run `kalypso init` first.", err=True)
        sys.exit(1)

    from kalypso.ca import fingerprint, verify_key_permissions
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    click.echo(f"CA Directory:   {data_dir}")
    click.echo(f"Subject:        {cert.subject.rfc4514_string()}")
    click.echo(f"Fingerprint:    {fingerprint(cert)}")
    click.echo(f"Not Before:     {cert.not_valid_before_utc}")
    click.echo(f"Not After:      {cert.not_valid_after_utc}")

    if key_path.exists():
        perms_ok = verify_key_permissions(key_path)
        mode = oct(key_path.stat().st_mode & 0o777)
        if perms_ok:
            click.echo(f"Key Security:   {mode} (secure)")
        else:
            click.echo(f"Key Security:   {mode} (INSECURE — run: chmod 600 {key_path})", err=True)
