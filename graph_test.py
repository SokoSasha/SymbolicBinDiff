# import networkx as nx
# from networkx.algorithms.isomorphism import GraphMatcher
#
# # Создание графов
# G1 = nx.DiGraph()
# G1.add_edges_from([(1, 2), (1, 3), (2, 3), (2, 4), (3, 4)])
#
# G2 = nx.DiGraph()
# G2.add_edges_from([(20, 30), (20, 40), (30, 40)])
#
# # Поиск частично изоморфных графов
# GM = GraphMatcher(G1, G2)
#
# # Вывод результатов
# if GM.subgraph_is_isomorphic():
#     print("Частично изоморфные графы найдены:")
#     for n1, n2 in GM.mapping.items():
#         print(f"{n1} из G1 соответствует {n2} из G2")
# else:
#     print("Частично изоморфные графы не найдены.")


def find_subgraph_isomorphism(subgraph, graph):
    """
    Найти изоморфизм между заданным подграфом и заданным графом.

    Args:
        subgraph (dict): Подграф в виде словаря, где ключи - узлы,
                         а значения - списки их соседей.
        graph (dict): Граф в виде словаря, где ключи - узлы,
                      а значения - списки их соседей.

    Returns:
        dict: Словарь, представляющий изоморфизм между подграфом и графом,
              где ключи - узлы в подграфе, а значения - соответствующие узлы в графе.
              Если изоморфизм не найден, возвращается None.
    """
    # Проверяем, что подграф является подмножеством графа
    if not set(subgraph).issubset(set(graph)):
        return None

    # Составляем список узлов подграфа в порядке их добавления
    nodes = list(subgraph.keys())

    # Рекурсивно ищем изоморфизм, начиная со всех узлов подграфа
    for node in nodes:
        isomorphism = find_subgraph_isomorphism_helper(node, subgraph, graph, {})
        if isomorphism is not None:
            return isomorphism

    # Изоморфизм не найден
    return None


def find_subgraph_isomorphism_helper(node, subgraph, graph, isomorphism):
    """
    Вспомогательная функция для поиска изоморфизма между подграфом и графом.

    Args:
        node (any): Узел в подграфе.
        subgraph (dict): Подграф в виде словаря, где ключи - узлы,
                         а значения - списки их соседей.
        graph (dict): Граф в виде словаря, где ключи - узлы,
                      а значения - списки их соседей.
        isomorphism (dict): Частичное отображение узлов подграфа в узлы графа.

    Returns:
        dict: Словарь, представляющий изоморфизм между подграфом и графом,
              где ключи - узлы в подграфе, а значения - соответствующие узлы в графе.
              Если изоморфизм не найден, возвращается None.
    """
    # Если все узлы в подграфе имеют соответствия в графе,
    # значит, мы нашли изоморфизм
    if len(isomorphism) == len(subgraph):
        return isomorphism


G1 = {'a': ['b', 'c'], 'b': ['c', 'd'], 'c': 'd'}
G2 = {'a': ['b', 'c'], 'c': 'b'}

print(find_subgraph_isomorphism(G1, G2))