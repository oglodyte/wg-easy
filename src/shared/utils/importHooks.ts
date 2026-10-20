/** Editable import defaults; no commands run until the interface is enabled. */
export const LEGACY_IMPORT_DEFAULT_EGRESS = `"$(ip -4 route show default | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"`;

export function legacyImportHooks(ipv6: boolean) {
  function rules(action: 'A' | 'D') {
    const ipv4 = [
      `iptables -t nat -${action} POSTROUTING -s {{ipv4Cidr}} -o ${LEGACY_IMPORT_DEFAULT_EGRESS} -j MASQUERADE`,
      `iptables -${action} INPUT -p udp -m udp --dport {{port}} -j ACCEPT`,
      `iptables -${action} FORWARD -i {{name}} -j ACCEPT`,
      `iptables -${action} FORWARD -o {{name}} -j ACCEPT`,
    ];
    const ipv6Rules = ipv6
      ? [
          `ip6tables -t nat -${action} POSTROUTING -s {{ipv6Cidr}} -o {{device}} -j MASQUERADE`,
          `ip6tables -${action} INPUT -p udp -m udp --dport {{port}} -j ACCEPT`,
          `ip6tables -${action} FORWARD -i {{name}} -j ACCEPT`,
          `ip6tables -${action} FORWARD -o {{name}} -j ACCEPT`,
        ]
      : [];
    return [...ipv4, ...ipv6Rules].join('; ') + ';';
  }
  return { preUp: '', postUp: rules('A'), preDown: '', postDown: rules('D') };
}
