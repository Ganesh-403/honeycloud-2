"""
Report Generator for HoneyCloud-X
Generates CSV reports of attack events
"""
import csv
import logging
from datetime import datetime
from typing import List

logger = logging.getLogger(__name__)


def generate_csv_report(events: List[dict], filename: str = None) -> str:
    """
    Generate CSV report from attack events.
    
    Args:
        events: List of attack event dictionaries
        filename: Output filename (optional)
        
    Returns:
        Path to generated CSV file
    """
    if not filename:
        filename = f"reports/attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            if not events:
                csvfile.write("No attack events to report\n")
                return filename
            
            fieldnames = ['id', 'timestamp', 'service', 'source_ip', 'username', 
                         'severity', 'ai_label', 'threat_score', 'command']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for event in events:
                writer.writerow({k: event.get(k, '') for k in fieldnames})
        
        logger.info(f"✅ CSV report generated: {filename}")
        return filename
    
    except Exception as e:
        logger.error(f"❌ Error generating CSV report: {e}")
        raise


def generate_pdf_report(events: List[dict], stats: dict, filename: str = None) -> str:
    """
    Generate a simple text-based report (PDF generation requires matplotlib).
    For now, this creates a detailed text file.
    
    Args:
        events: List of attack event dictionaries
        stats: Statistics dictionary
        filename: Output filename (optional)
        
    Returns:
        Path to generated report file
    """
    if not filename:
        filename = f"reports/attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("HoneyCloud-X Security Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")
            
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 70 + "\n")
            f.write(f"Total Attack Events: {stats.get('total_events', 0)}\n\n")
            
            f.write("Events by Service:\n")
            for service, count in stats.get('events_by_service', {}).items():
                f.write(f"  {service}: {count}\n")
            
            f.write("\nEvents by Severity:\n")
            for severity, count in stats.get('events_by_severity', {}).items():
                f.write(f"  {severity}: {count}\n")
            
            f.write("\nAI Classification:\n")
            for label, count in stats.get('ai_labels', {}).items():
                f.write(f"  {label}: {count}\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("RECENT ATTACK EVENTS (Last 20)\n")
            f.write("=" * 70 + "\n\n")
            
            for event in events[:20]:
                f.write(f"Event ID: {event.get('id')}\n")
                f.write(f"  Timestamp: {event.get('timestamp')}\n")
                f.write(f"  Service: {event.get('service')}\n")
                f.write(f"  Source IP: {event.get('source_ip')}\n")
                f.write(f"  Username: {event.get('username', 'N/A')}\n")
                f.write(f"  Severity: {event.get('severity')}\n")
                f.write(f"  AI Label: {event.get('ai_label')}\n")
                f.write(f"  Threat Score: {event.get('threat_score')}\n")
                if event.get('command'):
                    f.write(f"  Command: {event.get('command')}\n")
                f.write("\n")
        
        logger.info(f"✅ Report generated: {filename}")
        return filename
    
    except Exception as e:
        logger.error(f"❌ Error generating report: {e}")
        raise
