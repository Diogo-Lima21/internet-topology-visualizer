import json
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import matplotlib.colors as mcolors
import matplotlib

matplotlib.use('TkAgg')

DATA_FILE = 'network_data.json'

COUNTRY_NAMES_PT = {
    "US": "Estados Unidos", "CA": "Canadá", "BR": "Brasil", "AR": "Argentina", "MX": "México",
    "CO": "Colômbia", "CL": "Chile", "PE": "Peru",
    "GB": "Reino Unido", "DE": "Alemanha", "FR": "França", "ES": "Espanha", "IT": "Itália",
    "RU": "Rússia", "NL": "Holanda", "SE": "Suécia", "DK": "Dinamarca", "NO": "Noruega",
    "FI": "Finlândia", "PL": "Polônia",
    "JP": "Japão", "CN": "China", "IN": "Índia", "KR": "Coreia do Sul", "SG": "Singapura",
    "ID": "Indonésia", "TH": "Tailândia", "PK": "Paquistão", "PH": "Filipinas",
    "AU": "Austrália", "NZ": "Nova Zelândia",
    "ZA": "África do Sul", "EG": "Egito", "NG": "Nigéria", "KE": "Quênia", "DZ": "Argélia",
    "MA": "Marrocos", "SN": "Senegal",
    "EU": "União Europeia",
    "Unknown": "Desconhecido"
}


def load_data(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Erro: Arquivo '{filepath}' não encontrado. Certifique-se de que o coletor de dados foi executado.")
        return None
    except json.JSONDecodeError as e:
        print(f"Erro ao decodificar JSON de '{filepath}': {e}")
        return None

def is_private_ip(ip):
    parts = list(map(int, ip.split('.')))
    if parts[0] == 10: return True
    if parts[0] == 172 and 16 <= parts[1] <= 31: return True
    if parts[0] == 192 and parts[1] == 168: return True
    if parts[0] == 127: return True
    return False

def create_networkx_graph(data):
    G = nx.DiGraph()
    unique_countries = set()

    for site_data in data:
        main_ip = site_data.get("main_ip")
        main_ip_geo = site_data.get("main_ip_geolocation", {})
        domain = site_data.get("domain", "Unknown Domain")

        if main_ip and not is_private_ip(main_ip):
            country_code = main_ip_geo.get("country", "Unknown")
            if country_code is None:
                country_code = "Unknown"
            
            country_name = COUNTRY_NAMES_PT.get(country_code, country_code)
            unique_countries.add(country_name)
            
            G.add_node(main_ip,
                       label=domain, 
                       type='main_ip',
                       domain=domain,
                       country_code=country_code,
                       country=country_name,
                       city=main_ip_geo.get("city", "N/A"),
                       org=main_ip_geo.get("org", "N/A"),
                       whois=site_data.get("whois", {}))

        previous_hop_ip = main_ip
        if site_data.get("traceroute_hops"):
            for hop in site_data["traceroute_hops"]:
                current_hop_ip = hop.get("ip_address")
                
                hop_geo = hop.get("geolocation") 
                if hop_geo is None:
                    hop_geo = {} 

                hop_hostname = hop.get("hostname", "N/A")
                hop_number = hop.get("hop_number")

                if current_hop_ip and not is_private_ip(current_hop_ip):
                    country_code = hop_geo.get("country", "Unknown")
                    if country_code is None:
                        country_code = "Unknown"

                    country_name = COUNTRY_NAMES_PT.get(country_code, country_code)
                    unique_countries.add(country_name)
                    
                    if not G.has_node(current_hop_ip):
                        G.add_node(current_hop_ip,
                                   label=hop_hostname if hop_hostname != 'N/A' else current_hop_ip, 
                                   type='hop_ip',
                                   country_code=country_code,
                                   country=country_name,
                                   city=hop_geo.get("city", "N/A"),
                                   org=hop_geo.get("org", "N/A"),
                                   hop_number=hop_number)
                    
                    if previous_hop_ip and not is_private_ip(previous_hop_ip):
                        G.add_edge(previous_hop_ip, current_hop_ip, hop_num=hop_number)
                    
                    previous_hop_ip = current_hop_ip

    return G, sorted(list(unique_countries))

def visualize_graph_matplotlib(G, countries_pt_names):
    """Visualiza o grafo NetworkX usando Matplotlib, com nomes de cidades/países nos rótulos."""

    plt.figure(figsize=(15, 12))
    
    
    num_countries = len(countries_pt_names)
    
   
   
    
    cmap = plt.colormaps['tab20']
    
  
    country_color_map = {}
    for i, country in enumerate(countries_pt_names):
        country_color_map[country] = cmap(i / num_countries) 


    node_colors = []
    node_labels = {}
    node_sizes = []
    node_edge_colors = []

    for node in G.nodes():
        node_data = G.nodes[node]
        country_name = node_data.get('country', 'Desconhecido') 
        node_colors.append(country_color_map.get(country_name, '#cccccc'))

       
        label_text = "" 
        node_type = node_data.get('type')

        if node_type == 'main_ip':
           
            label_text = node_data.get('domain')
            if not label_text or label_text == "N/A":
                label_text = node 
        elif node_type == 'hop_ip':
            
            label_text = node_data.get('city')
            if not label_text or label_text == "N/A":
                label_text = node_data.get('hostname')
                if not label_text or label_text == "N/A":
                    label_text = node 
        else: 
            label_text = node
        
        node_labels[node] = label_text

        if node_type == 'main_ip': 
            node_sizes.append(300)
            node_edge_colors.append('black')
        else:
            node_sizes.append(150)
            node_edge_colors.append('gray')

    pos = nx.spring_layout(G, k=0.5, iterations=50, seed=42)

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.9,
                           edgecolors=node_edge_colors, linewidths=1.5)
    
    nx.draw_networkx_edges(G, pos, edgelist=G.edges(), arrows=True, arrowsize=10,
                           edge_color='gray', alpha=0.6, width=0.8)

    nx.draw_networkx_labels(G, pos, labels=node_labels, font_size=7, font_color='black')
    
    plt.title('Visualização de Topologia de Rede Global (Matplotlib)', fontsize=16)
    plt.axis('off')
    
    legend_elements = []
    for country_pt_name, color_rgb_tuple in country_color_map.items():
        hex_color = mcolors.to_hex(color_rgb_tuple) 
        legend_elements.append(plt.Line2D([0], [0], marker='o', color='w', label=country_pt_name,
                                          markerfacecolor=hex_color, markersize=10))
    plt.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1, 1),
               title="Países", fontsize=9)

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    network_data = load_data(DATA_FILE)

    if network_data:
        G, unique_countries_pt = create_networkx_graph(network_data)
        if G.number_of_nodes() > 0:
            print(f"Grafo criado com {G.number_of_nodes()} nós e {G.number_of_edges()} arestas.")
            visualize_graph_matplotlib(G, unique_countries_pt)
        else:
            print("Nenhum nó válido foi adicionado ao grafo.")
    else:
        print("Não foi possível carregar os dados para visualização.")
