<?php

namespace App\Http\Controllers;

use DB;
use Illuminate\Http\Request;

class DNSController extends Controller
{
    // 其他记录
    private $qtype = ['A', 'A6', 'AAAA', 'AFSDB', 'ALIAS', 'CAA', 'CDNSKEY', 'CDS', 'CERT', 'CNAME', 'DHCID', 'DLV', 'DNSKEY', 'DNAME', 'DS', 'EUI48', 'EUI64', 'HINFO', 'IPSECKEY', 'KEY', 'KX', 'LUA', 'LOC', 'MAILA', 'MAILB', 'MINFO', 'MR', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'OPENPGPKEY', 'OPT', 'RKEY', 'RP', 'RRSIG', 'SIG', 'SPF', 'SRV', 'SSHFP', 'TLSA', 'TKEY', 'TSIG', 'TXT', 'WKS', 'URI'];
    // RNDS域名
    private $suffix = 'defense.gov';
    // DNS服务器域名
    private $ns1 = 'ns1.taterli.com';
    private $ns2 = 'ns2.taterli.com';
    // Hostmaster域名
    private $hm = 'hostmaster.taterli.com';

    public function lookup(Request $request)
    {
        $ret = array();

        if (strcmp($request->qtype, "SOA") == 0) {
            return response()->json(["result" => [["qtype" => $request->qtype, "qname" => $request->qname, "content" => $this->ns1." ".$this->hm." 2021092900 28800 7200 604800 86400", "ttl" => 86400]]]);
        }

        if (strcmp($request->qtype, "PTR") == 0 || strcmp($request->qtype, "ANY") == 0) {
            if (substr($request->qname, strpos($request->qname, 'arpa.')) === 'arpa.') {
                $records = DB::table('records')->where('type', 'PTR')->where('name', str_replace('arpa.', 'arpa', $request->qname))->get();
                // 先从数据库查找
                foreach ($records as $record) {
                    array_push($ret, ["qtype" => 'PTR', "qname" => $request->qname, "content" => $record->content, $record->ttl]);
                }
                // 如果没有结果,就要判断请求的是不是刚好是PTR了,是的话伪造一个.
                if ($records->count() == 0) {
                    if (substr($request->qname, strpos($request->qname, '.in-addr.arpa.')) === '.in-addr.arpa.') {
                        $domain = str_replace('.in-addr.arpa.', '', $request->qname);
                        $domain = explode('.', $domain);
                        $domain = array_reverse($domain);
                        if (filter_var(implode('.', $domain), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                            $domain = implode('-', $domain);
                            $domain = $domain . '.ipv4.' . $this->suffix;
                            array_push($ret, ["qtype" => 'PTR', "qname" => $request->qname, "content" => $domain, 30]);
                        }
                    } else {
                        if (substr($request->qname, strpos($request->qname, '.ip6.arpa.')) === '.ip6.arpa.') {
                            $domain = str_replace('.ip6.arpa.', '', $request->qname);
                            $domain = strrev($domain);
                            $domain = str_replace('.', '', $domain);
                            $domain = str_split($domain, 4);
                            if (filter_var(implode(':', $domain), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                                $domain = implode('-', $domain);
                                $domain = $domain . '.ipv6.' . $this->suffix;
                                array_push($ret, ["qtype" => 'PTR', "qname" => $request->qname, "content" => $domain, 30]);
                            }
                        }
                    }
                }
            }
        }

        // 这里特定的域名经过这里解释,以匹配RDNS的配置.
        if (strcmp($request->qtype, "A") == 0 || strcmp($request->qtype, "ANY") == 0) {
            if (substr($request->qname, strpos($request->qname, '.ipv4.' . $this->suffix . '.')) === '.ipv4.' . $this->suffix . '.') {
                $records = DB::table('records')->where('type', 'A')->where('name', str_replace($this->suffix . '.', $this->suffix, $request->qname))->get();
                // 先从数据库查找
                foreach ($records as $record) {
                    array_push($ret, ["qtype" => 'A', "qname" => $request->qname, "content" => $record->content, $record->ttl]);
                }
                // 如果找不到就编一个
                if ($records->count() == 0) {
                    $ip = $request->qname;
                    $ip = str_replace('.ipv4.'.$this->suffix.'.', '', $ip);
                    $ip = str_replace('-', '.', $ip);
                    array_push($ret, ["qtype" => 'A', "qname" => $request->qname, "content" => $ip, 30]);
                }
            }
        }

        if (strcmp($request->qtype, "AAAA") == 0 || strcmp($request->qtype, "ANY") == 0) {
            if (substr($request->qname, strpos($request->qname, '.ipv6.' . $this->suffix . '.')) === '.ipv6.' . $this->suffix . '.') {
                $records = DB::table('records')->where('type', 'AAAA')->where('name', str_replace($this->suffix . '.', $this->suffix, $request->qname))->get();
                // 先从数据库查找
                foreach ($records as $record) {
                    array_push($ret, ["qtype" => 'AAAA', "qname" => $request->qname, "content" => $record->content, $record->ttl]);
                }
                // 如果找不到就编一个
                if ($records->count() == 0) {
                    $ip = $request->qname;
                    $ip = str_replace('.ipv6.'.$this->suffix.'.', '', $ip);
                    $ip = str_replace('-', ':', $ip);
                    array_push($ret, ["qtype" => 'AAAA', "qname" => $request->qname, "content" => $ip, 30]);
                }
            }
        }

        // NS提取模式
        if (substr($request->qname, strpos($request->qname, '.in-addr.arpa.')) === '.in-addr.arpa.') {
            $dot = count(explode('.', $request->qname));
            if ($dot >= 4 && $dot <= 6) {
                $records = DB::table('records')->where('type', 'NS')->where('name', trim($request->qname, '.'))->get();
                foreach ($records as $record) {
                    array_push($ret, ["qtype" => $qtype, "qname" => $request->qname, "content" => $record->content, $record->ttl]);
                }
                if ($records->count() == 0) {
                    array_push($ret, ["qtype" => 'NS', "qname" => trim($request->qname, '.'), "content" => $this->ns1, 3600]);
                    array_push($ret, ["qtype" => 'NS', "qname" => trim($request->qname, '.'), "content" => $this->ns2, 3600]);
                }
            }
        }else if (substr($request->qname, strpos($request->qname, '.ip6.arpa.')) === '.ip6.arpa.') {
            $dot = count(explode('.', $request->qname));
            if ($dot >= 11 && $dot <= 15) {
                $records = DB::table('records')->where('type', 'NS')->where('name', trim($request->qname, '.'))->get();
                foreach ($records as $record) {
                    array_push($ret, ["qtype" => $qtype, "qname" => $request->qname, "content" => $record->content, $record->ttl]);
                }
                if ($records->count() == 0) {
                    array_push($ret, ["qtype" => 'NS', "qname" => trim($request->qname, '.'), "content" => $this->ns1, 3600]);
                    array_push($ret, ["qtype" => 'NS', "qname" => trim($request->qname, '.'), "content" => $this->ns2, 3600]);
                }
            }
        }else{
            // 普通域名
            $domain = trim($request->qname, '.');
            $domain = explode('.', $domain);
            $domain = $domain[count($domain) - 2] . '.' . $domain[count($domain) - 1];
            $records = DB::table('records')->where('type', 'NS')->where('name', trim($request->qname, '.'))->get();
            foreach ($records as $record) {
                array_push($ret, ["qtype" => $qtype, "qname" => $request->qname, "content" => $record->content, $record->ttl]);
            }
            if ($records->count() == 0) {
                array_push($ret, ["qtype" => 'NS', "qname" => trim($request->qname, '.'), "content" => $this->ns1, 3600]);
                array_push($ret, ["qtype" => 'NS', "qname" => trim($request->qname, '.'), "content" => $this->ns2, 3600]);
            }
        }

        // 其他记录
        foreach ($this->qtype as $qtype) {
            // 这两个涉及RDNS情况刚才已经处理过了,因此不重复处理.
            if (strcmp($qtype, 'A') == 0) {
                if (substr($request->qname, strpos($request->qname, '.ipv4.' . $this->suffix . '.')) === '.ipv4.' . $this->suffix . '.') {
                    continue;
                }
            }

            if (strcmp($qtype, 'AAAA') == 0) {
                if (substr($request->qname, strpos($request->qname, '.ipv6.' . $this->suffix . '.')) === '.ipv6.' . $this->suffix . '.') {
                    continue;
                }
            }

            if (substr($request->qname, strpos($request->qname, '.in-addr.arpa.')) === '.in-addr.arpa.') {
                continue;
            }

            if (substr($request->qname, strpos($request->qname, '.ip6.arpa.')) === '.ip6.arpa.') {
                continue;
            }

            // 泛解释逻辑,检索出某域名结尾全部*内容.
            $records = DB::table('records')->where('type', $qtype)->where('name', 'like', '%*%.' . $domain)->get();
            // 检查当前域名是否出于这个*内.
            foreach ($records as $record) {
                $suffix = ltrim($record->name, '*') . '.';
                if (substr($request->qname, strpos($request->qname, $suffix)) === $suffix) {
                    // 进入这里就是匹配到泛解释
                    $records = DB::table('records')->where('type', $qtype)->where('name', '*.' . trim($suffix, '.'))->get();
                    foreach ($records as $record) {
                        if (strcmp($qtype, 'MX') == 0) {
                            array_push($ret, ["qtype" => $qtype, "qname" => $request->qname, "content" => $record->prio . ' ' . $record->content, $record->ttl]);
                        } else {
                            array_push($ret, ["qtype" => $qtype, "qname" => $request->qname, "content" => $record->content, $record->ttl]);
                        }
                    }
                }
            }

            // 就算做了泛解释,也可以做普通解释.
            if (strcmp($request->qtype, $qtype) == 0 || strcmp($request->qtype, "ANY") == 0) {
                $records = DB::table('records')->where('type', $qtype)->where('name', trim($request->qname, '.'))->get();
                foreach ($records as $record) {
                    if (strcmp($qtype, 'MX') == 0) {
                        array_push($ret, ["qtype" => $qtype, "qname" => $request->qname, "content" => $record->prio . ' ' . $record->content, $record->ttl]);
                    } else {
                        array_push($ret, ["qtype" => $qtype, "qname" => $request->qname, "content" => $record->content, $record->ttl]);
                    }
                }
            }
        }
        return response()->json(["result" => $ret]);
    }

    public function getAllDomainMetadata(Request $request)
    {
        return response()->json(["result" => ["PRESIGNED" => ["0"]]]);
    }
}
