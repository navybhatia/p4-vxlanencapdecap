// p4c-bfn -I/usr/share/p4c/p4include --target tofino-tna --o /tmp/tf_out SwitchVxlanEncapDecap.p4
#include <core.p4>
#include <tofino.p4>
#include <tofino1arch.p4>

header Ethernet_h {
   bit<48> dmac;
   bit<48> smac;
   bit<16> etherType;
}

header Ipv4_h {
   bit<4>  version;
   bit<4>  ihl;
   bit<6>  dscp;
   bit<2>  ecn;
   bit<16> totalLen;
   bit<16> ident;
   bit<3>  flags;
   bit<13> fragOffset;
   bit<8>  ttl;
   bit<8>  protocol;
   bit<16> chksum;
   bit<32> sip;
   bit<32> dip;

}

header Udp_h {
   bit<16> srcPort;
   bit<16> dstPort;
   bit<16> len;
   bit<16> chksum;
}

header Vxlan_h {
   bit<8>  flags;
   bit<24> reserved;
   bit<24> vni;
   bit<8>  reserved2;
}

@flexible header BridgeMeta_h {
   bit<48> encapDmac;
   bit<48> dmac;
   bit<24> vni;
   bit<32> vtepIp;
   bit<16> hash;
   bit<1> decap;
   bit<1> encap;
}

struct header_t {
   BridgeMeta_h  bridgeMeta;
   Ethernet_h    encapEthHdr;
   Ipv4_h        encapIpv4Hdr;
   Udp_h         encapUdpHdr;
   Ethernet_h    outerEthHdr;
   Ipv4_h        outerIpv4Hdr;
   Udp_h         udpHdr;
   Vxlan_h       vxlanHdr;
   Ethernet_h    innerEthHdr;
   Ipv4_h        innerIpv4Hdr;
}

struct metadata_t {
   bit<10> vrfId;
}

parser SwitchIngressParser(
             packet_in pkt,
             out header_t hdr,
             out metadata_t meta,
             out ingress_intrinsic_metadata_t ig_intr_md) {

   state start {
      pkt.extract(ig_intr_md);
      transition parsePortMeta;
   }

   state parsePortMeta {
      pkt.advance(64);
      //Phase0Pack port_md = port_metadata_unpack<Phase0Pack>(pkt);
      //meta.ig_intr_md.ingress_port = ig_intr_md.ingress_port;
      transition parseEthernet;
   }

   state parseEthernet {
      pkt.extract( hdr.outerEthHdr );
      transition select( hdr.outerEthHdr.etherType ) {
         0x800 : parseOuterIpv4Hdr;
         default : accept;
      }
   }

   state parseOuterIpv4Hdr {
      pkt.extract( hdr.outerIpv4Hdr );
      transition select( hdr.outerIpv4Hdr.protocol ) {
         17 : parseUdpHdr;
         default : accept;
      }
   }

   state parseUdpHdr {
      pkt.extract( hdr.udpHdr );
      transition select( hdr.udpHdr.dstPort ) {
         4789 : parseVxlanHdr;
         default : accept;
      }
   }

   state parseVxlanHdr {
      pkt.extract( hdr.vxlanHdr );
      transition parseInnerEthernet;
   }

   state parseInnerEthernet {
      pkt.extract( hdr.innerEthHdr );
      transition select( hdr.innerEthHdr.etherType ) {
         0x800 : parseInnerIpv4Hdr;
         default : accept;
      }
   }

   state parseInnerIpv4Hdr {
      pkt.extract( hdr.innerIpv4Hdr );
      transition accept;
   }
}

control doHash(
      inout header_t hdr,
      inout metadata_t meta,
      in ingress_intrinsic_metadata_t ig_intr_md,
      in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
      inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
      inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

      Hash<bit<16>>(HashAlgorithm_t.CRC16) hashIpv4Hdr;
      Hash<bit<16>>(HashAlgorithm_t.CRC16) hashInnerIpv4Hdr;
      action hashOuterIpv4() {
         hdr.bridgeMeta.setValid();
         hdr.bridgeMeta.hash = hashIpv4Hdr.get<tuple<bit<32>, bit<32>, bit<8>>>({hdr.outerIpv4Hdr.sip, hdr.outerIpv4Hdr.dip, hdr.outerIpv4Hdr.protocol});
      }
      action hashInnerIpv4() {
         hdr.bridgeMeta.setValid();
         hdr.bridgeMeta.hash = hashInnerIpv4Hdr.get<tuple<bit<32>, bit<32>, bit<8>>>({hdr.innerIpv4Hdr.sip, hdr.innerIpv4Hdr.dip, hdr.innerIpv4Hdr.protocol});
      }

      table hashCompute {
         actions = {
            hashOuterIpv4();
            hashInnerIpv4();
         }
         key = {
           hdr.vxlanHdr.isValid() : exact ;
         }
         size = 2;
         default_action = hashOuterIpv4();
      }

      apply {
         hashCompute.apply();
      }
}

control doVrfLookup(
      inout header_t hdr,
      inout metadata_t meta,
      in ingress_intrinsic_metadata_t ig_intr_md,
      in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
      inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
      inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

      action setVrf( bit<10> vrfId ) {
         meta.vrfId = vrfId;
      }

      table vniToVrf {
         actions = {
            setVrf();
         }
         key = {
            hdr.vxlanHdr.vni : exact;
         }
         size = 1024;
         default_action = setVrf(0);
      }

      table portToVrf {
         actions = {
            setVrf();
         }
         key = {
            ig_intr_md.ingress_port : exact;
         }
         size = 512;
         default_action = setVrf(0);
      }

      apply {
         if( hdr.vxlanHdr.isValid() == false ) {
            portToVrf.apply();
         } else {
            vniToVrf.apply();
         }
      }
}

control doL3Unicast(
      inout header_t hdr,
      inout metadata_t meta,
      in ingress_intrinsic_metadata_t ig_intr_md,
      in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
      inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
      inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

      action setNextHop( bit<9> egressPort, bit<48> dmac ) {
         ig_intr_md_for_tm.ucast_egress_port = egressPort;
         hdr.bridgeMeta.dmac = dmac;
      }

      action setEncapNextHop( bit<9> egressPort, bit<48> encapDmac, bit<48> dmac, bit<24> vni, bit<32> vtepIp ) {
         setNextHop( egressPort, dmac );
         hdr.bridgeMeta.encapDmac = encapDmac;
         hdr.bridgeMeta.vni = vni;
         hdr.bridgeMeta.vtepIp = vtepIp;
         hdr.bridgeMeta.encap = 1;
      }

      action setDecapNextHop( bit<9> egressPort, bit<48> dmac ) {
         setNextHop( egressPort, dmac );
         hdr.bridgeMeta.decap = 1;
      }

      action setDecapAndEncapNextHop( bit<9> egressPort, bit<48> encapDmac, bit<48> dmac, bit<24> vni, bit<32> vtepIp ) {
         setEncapNextHop( egressPort, encapDmac, dmac, vni, vtepIp );
         hdr.bridgeMeta.decap = 1;
      }

      table outerRouting {
         actions = {
            setNextHop();
            setEncapNextHop();
            @defaultonly NoAction();
         }
         key = {
            meta.vrfId : exact;
            hdr.outerIpv4Hdr.dip : lpm;
         }
         size = 1024;
         default_action = NoAction();
      }

      table innerRouting {
         actions = {
            setDecapNextHop();
            setDecapAndEncapNextHop();
            @defaultonly NoAction();
         }
         key = {
            meta.vrfId : exact;
            hdr.innerIpv4Hdr.dip : lpm;
         }
         size = 1024;
         default_action = NoAction();
      }

      apply {
         if( hdr.vxlanHdr.isValid() == false ) {
            outerRouting.apply();
         } else {
            innerRouting.apply();
         }
      }
}


control SwitchIngress(
      inout header_t hdr,
      inout metadata_t meta,
      in ingress_intrinsic_metadata_t ig_intr_md,
      in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
      inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
      inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

      doHash() doHash_0;
      doVrfLookup() doVrfLookup_0;
      doL3Unicast() doL3Unicast_0;
      apply {
         doHash_0.apply( hdr, meta, ig_intr_md, ig_intr_md_from_prsr, ig_intr_md_for_dprsr, ig_intr_md_for_tm );
         doVrfLookup_0.apply( hdr, meta, ig_intr_md, ig_intr_md_from_prsr, ig_intr_md_for_dprsr, ig_intr_md_for_tm );
         doL3Unicast_0.apply( hdr, meta, ig_intr_md, ig_intr_md_from_prsr, ig_intr_md_for_dprsr, ig_intr_md_for_tm );
      }
}

control SwitchIngressDeparser(
      packet_out pkt,
      inout header_t hdr,
      in metadata_t meta,
      in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {
      apply {
         pkt.emit(hdr.outerEthHdr);
         pkt.emit(hdr.outerIpv4Hdr);
         pkt.emit(hdr.udpHdr);
         pkt.emit(hdr.vxlanHdr);
         pkt.emit(hdr.innerEthHdr);
         pkt.emit(hdr.innerIpv4Hdr);
     }
}

parser SwitchEgressParser(
      packet_in pkt,
      out header_t hdr,
      out metadata_t meta,
      out egress_intrinsic_metadata_t eg_intr_md) {

   state start {
      pkt.extract<egress_intrinsic_metadata_t>(eg_intr_md);
      transition parseBridgeMetadata;
   }

   state parseBridgeMetadata {
      pkt.extract(hdr.bridgeMeta);
      transition parseEthernet;
   }

   state parseEthernet {
      pkt.extract( hdr.outerEthHdr );
      transition select( hdr.outerEthHdr.etherType ) {
         0x800 : parseOuterIpv4Hdr;
         default : accept;
      }
   }

   state parseOuterIpv4Hdr {
      pkt.extract( hdr.outerIpv4Hdr );
      transition select( hdr.outerIpv4Hdr.protocol ) {
         17 : parseUdpHdr;
         default : accept;
      }
   }

   state parseUdpHdr {
      pkt.extract( hdr.udpHdr );
      transition select( hdr.udpHdr.dstPort ) {
         4789 : parseVxlanHdr;
         default : accept;
      }
   }

   state parseVxlanHdr {
      pkt.extract( hdr.vxlanHdr );
      transition parseInnerEthernet;
   }

   state parseInnerEthernet {
      pkt.extract( hdr.innerEthHdr );
      transition select( hdr.innerEthHdr.etherType ) {
         0x800 : parseInnerIpv4Hdr;
         default : accept;
      }
   }

   state parseInnerIpv4Hdr {
      pkt.extract( hdr.innerIpv4Hdr );
      transition accept;
   }

}

control doPacketRewrite(
      inout header_t hdr,
      inout metadata_t meta,
      in egress_intrinsic_metadata_t eg_intr_md,
      in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
      inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
      inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

      action macRewrite( bit<48> smac ) {
         hdr.outerEthHdr.dmac = hdr.bridgeMeta.dmac;
         hdr.outerEthHdr.smac = smac;
      }

      action noEncapRewrite( bit<48> smac ) {
         macRewrite( smac );
         // dec ttl
         hdr.outerIpv4Hdr.ttl = hdr.outerIpv4Hdr.ttl - 1;
      }

      action rewriteEncapHdr( bit<48> smac, bit<32> sip, bit<16> origLength ) {
         hdr.encapEthHdr.setValid();
         hdr.encapIpv4Hdr.setValid();
         hdr.encapUdpHdr.setValid();
         hdr.vxlanHdr.setValid();
         // add hdr info
         hdr.encapEthHdr.smac = smac;
         hdr.encapEthHdr.dmac = hdr.bridgeMeta.encapDmac;
         hdr.encapEthHdr.etherType = 0x800;

         hdr.encapIpv4Hdr.version = 0x4;
         hdr.encapIpv4Hdr.ihl = 0x5;
         hdr.encapIpv4Hdr.dscp = 0;
         hdr.encapIpv4Hdr.ecn = 0;
         hdr.encapIpv4Hdr.protocol = 17;
         hdr.encapIpv4Hdr.ttl = 64;
         hdr.encapIpv4Hdr.ident = 0;
         hdr.encapIpv4Hdr.flags = (bit<3>)3w2;
         hdr.encapIpv4Hdr.fragOffset = (bit<13>)13w0;
         hdr.encapIpv4Hdr.sip = sip;
         hdr.encapIpv4Hdr.dip = hdr.bridgeMeta.vtepIp;
         hdr.encapIpv4Hdr.totalLen = 50 + 14 + origLength;

         hdr.encapUdpHdr.srcPort = hdr.bridgeMeta.hash;
         hdr.encapUdpHdr.dstPort = 4789;
         hdr.encapUdpHdr.len = 30 + origLength;
         hdr.encapUdpHdr.chksum = 0;

         hdr.vxlanHdr.flags = 0;
         hdr.vxlanHdr.reserved = 0;
         hdr.vxlanHdr.vni = hdr.bridgeMeta.vni;
         hdr.vxlanHdr.reserved2 = 0;
      }

      action vxlanEncapRewrite( bit<48> smac, bit<32> sip ) {
         rewriteEncapHdr( smac, sip, hdr.outerIpv4Hdr.totalLen );
         macRewrite( smac );
         hdr.outerIpv4Hdr.ttl = hdr.outerIpv4Hdr.ttl - 1;
      }

      action removeEncapHdrs() {
         hdr.outerEthHdr.setInvalid();
         hdr.outerIpv4Hdr.setInvalid();
         hdr.udpHdr.setInvalid();
         hdr.vxlanHdr.setInvalid();
      }

      action vxlanDecapRewrite( bit<48> smac ) {
         removeEncapHdrs();
         hdr.innerEthHdr.dmac = hdr.bridgeMeta.dmac;
         hdr.innerEthHdr.smac = smac;
         hdr.innerIpv4Hdr.ttl = hdr.innerIpv4Hdr.ttl - 1;
      }
      action vxlanDecapAndEncapRewrite( bit<48> smac, bit<32> sip ) {
         removeEncapHdrs();
         vxlanDecapRewrite( smac );
         rewriteEncapHdr( smac, sip, hdr.innerIpv4Hdr.totalLen );
      }

      table packetRewrite {
         actions = {
            macRewrite();
            vxlanEncapRewrite();
            vxlanDecapRewrite();
            vxlanDecapAndEncapRewrite();
         }
         key = {
            hdr.bridgeMeta.encap : exact;
            hdr.bridgeMeta.decap : exact;
         }
         size = 4;
      }

      apply {
         packetRewrite.apply();
      }
}

control SwitchEgress(
      inout header_t hdr,
      inout metadata_t meta,
      in egress_intrinsic_metadata_t eg_intr_md,
      in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
      inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
      inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

      doPacketRewrite() doPacketRewrite_0;
      apply {
         doPacketRewrite_0.apply(hdr, meta, eg_intr_md, eg_intr_md_from_prsr, eg_intr_md_for_dprsr, eg_intr_md_for_oport);
      }
}

control SwitchEgressDeparser(
      packet_out pkt,
      inout header_t hdr,
      in metadata_t meta,
      in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

      Checksum() outerIpv4Checksum;
      Checksum() innerIpv4Checksum;
      apply {
         hdr.outerIpv4Hdr.chksum = outerIpv4Checksum.update(
                             {hdr.outerIpv4Hdr.version,
                              hdr.outerIpv4Hdr.ihl,
                              hdr.outerIpv4Hdr.dscp,
                              hdr.outerIpv4Hdr.ecn,
                              hdr.outerIpv4Hdr.totalLen,
                              hdr.outerIpv4Hdr.ident,
                              hdr.outerIpv4Hdr.flags,
                              hdr.outerIpv4Hdr.fragOffset,
                              hdr.outerIpv4Hdr.ttl,
                              hdr.outerIpv4Hdr.protocol,
                              hdr.outerIpv4Hdr.sip,
                              hdr.outerIpv4Hdr.dip});
         hdr.innerIpv4Hdr.chksum = innerIpv4Checksum.update(
                             {hdr.innerIpv4Hdr.version,
                              hdr.innerIpv4Hdr.ihl,
                              hdr.innerIpv4Hdr.dscp,
                              hdr.innerIpv4Hdr.ecn,
                              hdr.innerIpv4Hdr.totalLen,
                              hdr.innerIpv4Hdr.ident,
                              hdr.innerIpv4Hdr.flags,
                              hdr.innerIpv4Hdr.fragOffset,
                              hdr.innerIpv4Hdr.ttl,
                              hdr.innerIpv4Hdr.protocol,
                              hdr.innerIpv4Hdr.sip,
                              hdr.innerIpv4Hdr.dip});
         pkt.emit(hdr.outerEthHdr);
         pkt.emit(hdr.outerIpv4Hdr);
         pkt.emit(hdr.udpHdr);
         pkt.emit(hdr.vxlanHdr);
         pkt.emit(hdr.innerEthHdr);
         pkt.emit(hdr.innerIpv4Hdr);
     }

}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
