#!/usr/bin/env python3
import scrapy
import json
import re
from urllib.parse import urlparse
from scrapy.crawler import CrawlerProcess
from scrapy.downloadermiddlewares.offsite import OffsiteMiddleware

class CustomOffsiteMiddleware(OffsiteMiddleware):
    def should_follow(self, request, spider):
        if not self.host_regex:
            return True
        # This modification allows domains with ports
        host = urlparse(request.url).netloc.split(':')[0]
        return bool(self.host_regex.search(host))

class WebReconSpider(scrapy.Spider):
    name = 'ReconSpider'
    
    def __init__(self, start_url, *args, **kwargs):
        super(WebReconSpider, self).__init__(*args, **kwargs)
        self.start_urls = [start_url]
        self.allowed_domains = [urlparse(start_url).netloc.split(':')[0]]
        self.visited_urls = set()
        self.results = {
            'emails': set(),
            'links': set(),
            'external_files': set(),
            'js_files': set(),
            'form_fields': set(),
            'images': set(),
            'videos': set(),
            'audio': set(),
            'comments': set(),
        }
        
    def parse(self, response):
        self.visited_urls.add(response.url)

        # Only process text responses
        if response.headers.get('Content-Type', '').decode('utf-8').startswith('text'):
            # Extract emails
            emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text))
            self.results['emails'].update(emails)
        
            # Extract links
            links = response.css('a::attr(href)').getall()
            for link in links:
                if link.startswith('mailto:'):
                    continue
                parsed_link = urlparse(link)
                if not parsed_link.scheme:
                    link = response.urljoin(link)
                if urlparse(link).netloc == urlparse(response.url).netloc:
                    if link not in self.visited_urls:
                        yield response.follow(link, callback=self.parse)
                self.results['links'].add(link)
        
            # Extract external files (CSS, PDFs, etc.)
            external_files = response.css('link::attr(href), a::attr(href)').re(r'.*\.(css|pdf|docx?|xlsx?)$')
            for ext_file in external_files:
                self.results['external_files'].add(response.urljoin(ext_file))
        
            # Extract JS files
            js_files = response.css('script::attr(src)').getall()
            for js_file in js_files:
                self.results['js_files'].add(response.urljoin(js_file))
        
            # Extract form fields
            form_fields = response.css('input::attr(name), textarea::attr(name), select::attr(name)').getall()
            self.results['form_fields'].update(form_fields)
        
            # Extract images
            images = response.css('img::attr(src)').getall()
            for img in images:
                self.results['images'].add(response.urljoin(img))
        
            # Extract videos
            videos = response.css('video::attr(src), source::attr(src)').getall()
            for video in videos:
                self.results['videos'].add(response.urljoin(video))
        
            # Extract audio
            audio = response.css('audio::attr(src), source::attr(src)').getall()
            for aud in audio:
                self.results['audio'].add(response.urljoin(aud))
            
            # Extract comments
            comments = response.xpath('//comment()').getall()
            self.results['comments'].update(comments)
        else:
            # For non-text responses, just collect the URL
            self.results['external_files'].add(response.url)
        
        self.log(f"Processed {response.url}")

    def closed(self, reason):
        self.log("Crawl finished, converting results to JSON.")
        # Convert sets to lists for JSON serialization
        for key in self.results:
            self.results[key] = list(self.results[key])
        
        with open('results.json', 'w') as f:
            json.dump(self.results, f, indent=4)

        self.log(f"Results saved to results.json")

def run_crawler(start_url):
    process = CrawlerProcess(settings={
        'LOG_LEVEL': 'INFO',
        'DOWNLOADER_MIDDLEWARES': {
            '__main__.CustomOffsiteMiddleware': 500,
        }
    })
    process.crawl(WebReconSpider, start_url=start_url)
    process.start()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="ReconSpider")
    parser.add_argument("start_url", help="The starting URL for the web crawler")
    args = parser.parse_args()
    
    run_crawler(args.start_url)