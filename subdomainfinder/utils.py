import json
import logging
import re
from pathlib import Path
from typing import List, Set

from .enums import OutputFormat

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Set up logging configuration."""
    logger = logging.getLogger('subdomainfinder')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    )
    logger.addHandler(handler)
    
    return logger

def is_valid_subdomain(subdomain: str, base_domain: str) -> bool:
    """Validate if a subdomain is valid and belongs to the base domain."""
    # Loại bỏ các kết quả không hợp lệ
    if not subdomain or '*' in subdomain:  # Loại bỏ wildcard
        return False
    if '@' in subdomain:  # Loại bỏ địa chỉ email
        return False
    if not subdomain.endswith(base_domain):  # Phải là subdomain của domain gốc
        return False
    if subdomain == base_domain:  # Loại bỏ domain gốc
        return False
    
    # Kiểm tra định dạng subdomain hợp lệ
    subdomain_pattern = f"^[a-zA-Z0-9][-a-zA-Z0-9]*[a-zA-Z0-9]\\.{base_domain}$"
    return bool(re.match(subdomain_pattern, subdomain))

def clean_and_deduplicate_subdomains(subdomains: Set[str], base_domain: str) -> List[str]:
    """Clean and deduplicate subdomain results."""
    valid_subdomains = {
        subdomain.lower() for subdomain in subdomains 
        if is_valid_subdomain(subdomain.lower(), base_domain)
    }
    return sorted(list(valid_subdomains))

def save_results(subdomains: List[str], output_path: str, output_format: OutputFormat):
    """Save results to a file in the specified format."""
    output_path = Path(output_path)
    
    if output_format == OutputFormat.JSON:
        data = {
            'subdomains': subdomains,
            'count': len(subdomains)
        }
        output_path.write_text(json.dumps(data, indent=4))
    else:
        output_path.write_text('\n'.join(subdomains))