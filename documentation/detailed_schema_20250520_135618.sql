-- TWX Database Detailed Schema
-- Generated: 2025-05-20 13:56:18


-- Table: attack_techniques
CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id text NOT NULL,
    name text,
    description text,
    tactic text,
    data jsonb
);

-- Indexes
CREATE UNIQUE INDEX attack_techniques_pkey ON public.attack_techniques USING btree (technique_id);
CREATE INDEX idx_attack_techniques_tactic ON public.attack_techniques USING btree (tactic);

-- Table: capec_attack_mappings
CREATE TABLE IF NOT EXISTS capec_attack_mappings (
    capec_id text NOT NULL,
    technique_id text NOT NULL,
    confidence real,
    source text
);

-- Indexes
CREATE UNIQUE INDEX capec_attack_mappings_pkey ON public.capec_attack_mappings USING btree (capec_id, technique_id);

-- Table: capec_attack_patterns
CREATE TABLE IF NOT EXISTS capec_attack_patterns (
    capec_id text NOT NULL,
    name text,
    summary text,
    likelihood text,
    severity text,
    data jsonb
);

-- Indexes
CREATE UNIQUE INDEX capec_attack_patterns_pkey ON public.capec_attack_patterns USING btree (capec_id);

-- Table: cwe_capec_mappings
CREATE TABLE IF NOT EXISTS cwe_capec_mappings (
    cwe_id text NOT NULL,
    capec_id text NOT NULL,
    confidence real
);

-- Indexes
CREATE UNIQUE INDEX cwe_capec_mappings_pkey ON public.cwe_capec_mappings USING btree (cwe_id, capec_id);

-- Table: cwe_categories
CREATE TABLE IF NOT EXISTS cwe_categories (
    id integer NOT NULL,
    name text,
    description text,
    parent_category text
);

-- Indexes
CREATE UNIQUE INDEX cwe_categories_pkey ON public.cwe_categories USING btree (id);
CREATE UNIQUE INDEX cwe_categories_name_key ON public.cwe_categories USING btree (name);
CREATE INDEX idx_cwe_categories_name ON public.cwe_categories USING btree (name);
CREATE INDEX idx_cwe_categories_parent ON public.cwe_categories USING btree (parent_category);

-- Table: cwe_category_mappings
CREATE TABLE IF NOT EXISTS cwe_category_mappings (
    id integer NOT NULL,
    cwe_id text,
    category_id integer
);

-- Indexes
CREATE UNIQUE INDEX cwe_category_mappings_pkey ON public.cwe_category_mappings USING btree (id);
CREATE UNIQUE INDEX cwe_category_mappings_cwe_id_category_id_key ON public.cwe_category_mappings USING btree (cwe_id, category_id);

-- Table: metrics
CREATE TABLE IF NOT EXISTS metrics (
    id integer NOT NULL,
    vuln_id text,
    cvss_version text,
    base_score double precision,
    vector text,
    exploitability_score double precision,
    impact_score double precision,
    data jsonb
);

-- Indexes
CREATE UNIQUE INDEX metrics_pkey ON public.metrics USING btree (id);

-- Table: products
CREATE TABLE IF NOT EXISTS products (
    id integer NOT NULL,
    vendor text,
    product text,
    version text
);

-- Indexes
CREATE UNIQUE INDEX products_pkey ON public.products USING btree (id);
CREATE UNIQUE INDEX products_vendor_product_version_key ON public.products USING btree (vendor, product, version);
CREATE INDEX idx_products_vendor ON public.products USING btree (vendor);
CREATE INDEX idx_products_product ON public.products USING btree (product);

-- Table: vuln_references
CREATE TABLE IF NOT EXISTS vuln_references (
    id integer NOT NULL,
    vuln_id text,
    url text,
    source text,
    tags jsonb
);

-- Indexes
CREATE UNIQUE INDEX vuln_references_pkey ON public.vuln_references USING btree (id);
CREATE UNIQUE INDEX idx_vuln_references_vuln_id_url ON public.vuln_references USING btree (vuln_id, url);

-- Table: vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id text NOT NULL,
    description text,
    published timestamp without time zone,
    modified timestamp without time zone,
    reporter text,
    source text,
    known_exploited boolean,
    has_exploit boolean,
    has_cisa_advisory boolean,
    has_vendor_advisory boolean,
    base_score double precision,
    severity text,
    cvss_version text,
    cvss_vector text,
    exploitability_score double precision,
    impact_score double precision,
    attack_vector text,
    attack_complexity text,
    privileges_required text,
    user_interaction text,
    primary_cwe text,
    vuln_type text,
    epss_score double precision,
    epss_percentile double precision,
    product_count integer,
    reference_count integer,
    kev_date_added timestamp without time zone,
    kev_vendor_project text,
    kev_product text,
    kev_notes text,
    kev_required_action text,
    kev_due_date timestamp without time zone,
    data jsonb
);

-- Indexes
CREATE UNIQUE INDEX vulnerabilities_pkey ON public.vulnerabilities USING btree (id);
CREATE INDEX idx_vulnerabilities_published ON public.vulnerabilities USING btree (published);
CREATE INDEX idx_vulnerabilities_modified ON public.vulnerabilities USING btree (modified);
CREATE INDEX idx_vulnerabilities_known_exploited ON public.vulnerabilities USING btree (known_exploited);
CREATE INDEX idx_vulnerabilities_base_score ON public.vulnerabilities USING btree (base_score);
CREATE INDEX idx_vulnerabilities_severity ON public.vulnerabilities USING btree (severity);
CREATE INDEX idx_vulnerabilities_attack_vector ON public.vulnerabilities USING btree (attack_vector);
CREATE INDEX idx_vulnerabilities_attack_complexity ON public.vulnerabilities USING btree (attack_complexity);
CREATE INDEX idx_vulnerabilities_primary_cwe ON public.vulnerabilities USING btree (primary_cwe);
CREATE INDEX idx_vulnerabilities_vuln_type ON public.vulnerabilities USING btree (vuln_type);
CREATE INDEX idx_vulnerabilities_source ON public.vulnerabilities USING btree (source);
CREATE INDEX idx_vulnerabilities_data_gin ON public.vulnerabilities USING gin (data jsonb_path_ops);
CREATE INDEX idx_vulnerabilities_description_tsvector ON public.vulnerabilities USING gin (to_tsvector('english'::regconfig, description));

-- Table: vulnerability_attack_mappings
CREATE TABLE IF NOT EXISTS vulnerability_attack_mappings (
    id integer NOT NULL,
    vuln_id text,
    technique_id text,
    confidence double precision,
    source text
);

-- Indexes
CREATE UNIQUE INDEX vulnerability_attack_mappings_pkey ON public.vulnerability_attack_mappings USING btree (id);
CREATE UNIQUE INDEX vulnerability_attack_mappings_vuln_id_technique_id_key ON public.vulnerability_attack_mappings USING btree (vuln_id, technique_id);

-- Table: vulnerability_capec_mappings
CREATE TABLE IF NOT EXISTS vulnerability_capec_mappings (
    vuln_id text NOT NULL,
    capec_id text NOT NULL,
    confidence real,
    source text
);

-- Indexes
CREATE UNIQUE INDEX vulnerability_capec_mappings_pkey ON public.vulnerability_capec_mappings USING btree (vuln_id, capec_id);

-- Table: vulnerability_products
CREATE TABLE IF NOT EXISTS vulnerability_products (
    id integer NOT NULL,
    vuln_id text,
    product_id integer
);

-- Indexes
CREATE UNIQUE INDEX vulnerability_products_pkey ON public.vulnerability_products USING btree (id);
CREATE UNIQUE INDEX vulnerability_products_vuln_id_product_id_key ON public.vulnerability_products USING btree (vuln_id, product_id);

-- Table: vulnerability_weaknesses
CREATE TABLE IF NOT EXISTS vulnerability_weaknesses (
    id integer NOT NULL,
    vuln_id text,
    cwe_id text
);

-- Indexes
CREATE UNIQUE INDEX vulnerability_weaknesses_pkey ON public.vulnerability_weaknesses USING btree (id);
CREATE UNIQUE INDEX vulnerability_weaknesses_vuln_id_cwe_id_key ON public.vulnerability_weaknesses USING btree (vuln_id, cwe_id);

-- Table: weaknesses
CREATE TABLE IF NOT EXISTS weaknesses (
    cwe_id text NOT NULL,
    name text,
    description text,
    extended_description text,
    abstraction text,
    status text,
    category text,
    relationships jsonb,
    consequences jsonb,
    mitigations jsonb,
    detection_methods jsonb,
    examples jsonb,
    mitigations_text text,
    likelihood text,
    data jsonb
);

-- Indexes
CREATE UNIQUE INDEX weaknesses_pkey ON public.weaknesses USING btree (cwe_id);
CREATE INDEX idx_weaknesses_category ON public.weaknesses USING btree (category);
