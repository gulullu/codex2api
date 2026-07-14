\set ON_ERROR_STOP on

-- Required psql variables (unqualified identifiers; schema is public):
--   -v backup_table=ops_rb15_enrich_backup_YYYYMMDD_HHMMSS
--   -v manifest_table=ops_rb15_enrich_manifest_YYYYMMDD_HHMMSS
-- CREATE TABLE intentionally fails if either name already exists.

begin;
set local lock_timeout = '2s';
set local statement_timeout = '100s';

create table public.:"backup_table" (
    id bigint primary key,
    created_at timestamptz,
    source text not null,
    logical_request_id text,
    original_full_text text not null,
    original_text_preview text not null,
    original_full_md5 text not null,
    original_preview_md5 text not null,
    marker_pair boolean not null,
    source_supported boolean not null,
    full_parse_safe boolean not null,
    preview_parse_safe boolean not null,
    type_source_safe boolean not null,
    full_prefix_bytes integer not null,
    preview_prefix_bytes integer not null,
    backed_up_at timestamptz not null default clock_timestamp()
);

-- Unicode is encoded with PostgreSQL U& escapes so source-file encoding can
-- never silently change the retired writer's exact marker strings.
create temporary table rb15_candidate_analysis on commit drop as
with raw as (
    select p.*,
           (U&'\3010\5F52\5C5E\3011' || E'\n')::text as full_header,
           (U&'\300E' || 'sub2:')::text as preview_header,
           (U&'\300F' || ' ')::text as preview_terminator,
           U&'sub2 \7528\6237: '::text as sub2_prefix,
           U&'new-api \7528\6237: '::text as new_api_prefix,
           U&'\6C60\5B50\8D26\53F7: '::text as pool_prefix,
           U&'\7C7B\578B: '::text as type_prefix,
           U&'\771F\6F0F\653E(\4E0A\6E38\62E6\2192\8D26\53F7\98CE\9669)'::text as miss_type,
           U&'\672C\5730\62E6(\6211\4EEC\62E6\4E0B,\8FD4\56DE\5B98\65B9\6587\6848)'::text as local_type,
           strpos(p.full_text, E'\n\n') as full_separator,
           strpos(
               substring(p.text_preview from char_length(U&'\300E' || 'sub2:') + 1),
               U&'\300F' || ' '
           ) as preview_terminator_relative
    from public.prompt_filter_logs p
    where p.full_text is not null
      and p.text_preview is not null
), parsed as (
    select raw.*,
           left(full_text, char_length(full_header)) = full_header
             and left(text_preview, char_length(preview_header)) = preview_header
             as marker_pair,
           source in ('local_filter', 'semantic_review_disagreement', 'session_bleed', 'upstream_cyber_policy')
             as source_supported,
           case when full_separator > char_length(full_header)
                then regexp_split_to_array(
                       substring(
                         full_text
                         from char_length(full_header) + 1
                         for full_separator - char_length(full_header) - 1
                       ),
                       E'\n'
                     )
                else array[]::text[]
           end as block_lines,
           case when full_separator > 0
                then octet_length(left(full_text, full_separator + 1))
                else 0
           end as full_prefix_bytes,
           case when preview_terminator_relative > 0
                then octet_length(left(
                       text_preview,
                       char_length(preview_header)
                         + preview_terminator_relative
                         + char_length(preview_terminator) - 1
                     ))
                else 0
           end as preview_prefix_bytes,
           case when preview_terminator_relative > 0
                then substring(
                       text_preview
                       from char_length(preview_header) + 1
                       for preview_terminator_relative - 1
                     )
                else ''
           end as preview_tag
    from raw
), safety as (
    select parsed.*,
           marker_pair
             and full_separator > char_length(full_header)
             and full_prefix_bytes between 1 and 4096
             and cardinality(block_lines) in (3, 4)
             and left(block_lines[1], char_length(sub2_prefix)) = sub2_prefix
             and (
               (cardinality(block_lines) = 3
                 and left(block_lines[2], char_length(pool_prefix)) = pool_prefix
                 and char_length(block_lines[2]) > char_length(pool_prefix)
                 and left(block_lines[3], char_length(type_prefix)) = type_prefix)
               or
               (cardinality(block_lines) = 4
                 and left(block_lines[2], char_length(new_api_prefix)) = new_api_prefix
                 and left(block_lines[3], char_length(pool_prefix)) = pool_prefix
                 and char_length(block_lines[3]) > char_length(pool_prefix)
                 and left(block_lines[4], char_length(type_prefix)) = type_prefix)
             ) as full_parse_safe,
           marker_pair
             and preview_terminator_relative > 0
             and preview_prefix_bytes between 1 and 2048
             and preview_tag !~ E'[\r\n]'
             as preview_parse_safe,
           case
             when source = 'upstream_cyber_policy' then
               block_lines[cardinality(block_lines)] = type_prefix || miss_type
             else
               block_lines[cardinality(block_lines)] = type_prefix || local_type
           end as type_source_safe
    from parsed
)
select *
from safety
where marker_pair;

do $assert_candidates$
declare
    marker_count integer;
    safe_count integer;
begin
    select count(*),
           count(*) filter (
             where source_supported is true
               and full_parse_safe is true
               and preview_parse_safe is true
               and type_source_safe is true
           )
      into marker_count, safe_count
      from pg_temp.rb15_candidate_analysis;
    if marker_count = 0 then
        raise exception 'rb15 snapshot has zero legacy marker pairs';
    end if;
    if marker_count <> safe_count then
        raise exception 'rb15 unsafe candidate set: marker pairs %, safe %', marker_count, safe_count;
    end if;
end
$assert_candidates$;

insert into public.:"backup_table" (
    id, created_at, source, logical_request_id,
    original_full_text, original_text_preview,
    original_full_md5, original_preview_md5,
    marker_pair, source_supported, full_parse_safe, preview_parse_safe,
    type_source_safe, full_prefix_bytes, preview_prefix_bytes
)
select id, created_at, source, logical_request_id,
       full_text, text_preview, md5(full_text), md5(text_preview),
       marker_pair, source_supported, full_parse_safe, preview_parse_safe,
       type_source_safe, full_prefix_bytes, preview_prefix_bytes
from pg_temp.rb15_candidate_analysis
where marker_pair
  and source_supported
  and full_parse_safe
  and preview_parse_safe
  and type_source_safe
order by id;

create table public.:"manifest_table" (
    manifest_key text primary key check (manifest_key = 'rb15'),
    parser_version text not null,
    predicate_version text not null,
    target_table text not null,
    backup_table text not null,
    candidate_count integer not null check (candidate_count > 0),
    sealed boolean not null check (sealed),
    sealed_at timestamptz not null,
    database_oid oid not null,
    target_relid oid not null,
    target_relfilenode oid not null,
    backup_relid oid not null,
    backup_relfilenode oid not null,
    manifest_relid oid not null,
    manifest_relfilenode oid not null
);

insert into public.:"manifest_table" (
    manifest_key, parser_version, predicate_version,
    target_table, backup_table, candidate_count, sealed, sealed_at,
    database_oid, target_relid, target_relfilenode,
    backup_relid, backup_relfilenode, manifest_relid, manifest_relfilenode
)
select 'rb15', 'rb15-marker-v1', 'rb15-strict-v1',
       'public.prompt_filter_logs', 'public.' || :'backup_table', count(*)::integer,
       true, clock_timestamp(), d.oid, t.oid, t.relfilenode,
       b.oid, b.relfilenode, m.oid, m.relfilenode
from public.:"backup_table" snapshot
cross join pg_database d
cross join pg_class t
cross join pg_class b
cross join pg_class m
where d.datname = current_database()
  and t.oid = to_regclass('public.prompt_filter_logs')
  and b.oid = to_regclass('public.' || :'backup_table')
  and m.oid = to_regclass('public.' || :'manifest_table')
group by d.oid, t.oid, t.relfilenode, b.oid, b.relfilenode, m.oid, m.relfilenode;

create or replace function public.rb15_reject_snapshot_mutation()
returns trigger
language plpgsql
as $function$
begin
    raise exception 'rb15 sealed snapshot is immutable';
end
$function$;

create trigger rb15_snapshot_immutable
before insert or update or delete or truncate on public.:"backup_table"
for each statement execute function public.rb15_reject_snapshot_mutation();
alter table public.:"backup_table" enable always trigger rb15_snapshot_immutable;

create trigger rb15_manifest_immutable
before insert or update or delete or truncate on public.:"manifest_table"
for each statement execute function public.rb15_reject_snapshot_mutation();
alter table public.:"manifest_table" enable always trigger rb15_manifest_immutable;

revoke insert, update, delete, truncate on public.:"backup_table" from public;
revoke insert, update, delete, truncate on public.:"manifest_table" from public;

commit;

select :'backup_table' as backup_table,
       :'manifest_table' as manifest_table,
       candidate_count, sealed, sealed_at
from public.:"manifest_table"
where manifest_key = 'rb15';
