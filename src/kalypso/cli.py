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
    click.echo(f"  Certificate: {cert_path}")
    click.echo(f"  Private key: {key_path}")
    click.echo()

    # Try to auto-install into trust stores via mkcert
    from kalypso.mkcert import find_mkcert, install_ca_to_trust_store

    mkcert = find_mkcert()
    if mkcert.available:
        click.echo(f"Found mkcert ({mkcert.version}), installing CA into trust stores...")
        if install_ca_to_trust_store(cert_path):
            click.echo("CA installed into system trust store.")
        else:
            click.echo("Could not auto-install. Install manually (see below).", err=True)
            _print_manual_trust_instructions(cert_path)
    else:
        click.echo("Tip: install mkcert for automatic trust store setup (brew install mkcert)")
        click.echo()
        _print_manual_trust_instructions(cert_path)


def _print_manual_trust_instructions(cert_path: Path) -> None:
    click.echo("Trust the CA certificate in your system/browser:")
    click.echo(f"  macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {cert_path}")
    click.echo(f"  Ubuntu:  sudo cp {cert_path} /usr/local/share/ca-certificates/kalypso.crt && sudo update-ca-certificates")
    click.echo(f"  Fedora:  sudo trust anchor {cert_path}")


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


@main.command()
@click.pass_context
def serve(ctx: click.Context) -> None:
    """Start the Kalypso API server."""
    import uvicorn

    data_dir: Path = ctx.obj["data_dir"]
    cert_path = data_dir / "ca-cert.pem"
    key_path = data_dir / "ca-key.pem"

    # Pre-load the CA if it exists
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
    """Install the CA certificate into system trust stores (requires mkcert)."""
    data_dir: Path = ctx.obj["data_dir"]
    cert_path = data_dir / "ca-cert.pem"

    if not cert_path.exists():
        click.echo("No CA found. Run `kalypso init` first.", err=True)
        sys.exit(1)

    from kalypso.mkcert import find_mkcert, install_ca_to_trust_store

    mkcert = find_mkcert()
    if not mkcert.available:
        click.echo("mkcert is not installed. Install it first:", err=True)
        click.echo("  macOS:   brew install mkcert")
        click.echo("  Ubuntu:  sudo apt install mkcert")
        click.echo("  Other:   https://github.com/FiloSottile/mkcert#installation")
        click.echo()
        _print_manual_trust_instructions(cert_path)
        sys.exit(1)

    click.echo(f"Using mkcert ({mkcert.version}) to install CA into trust stores...")
    if install_ca_to_trust_store(cert_path):
        click.echo("CA installed into system trust store.")
    else:
        click.echo("Failed to install CA. Try manually:", err=True)
        _print_manual_trust_instructions(cert_path)
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
